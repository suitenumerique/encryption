import type { FastifyInstance, FastifyRequest } from 'fastify';
import { randomBytes, randomUUID } from 'node:crypto';

import { base64ToUint8, importPublicKeyFromBytes, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { verifyIdentityContinuity } from '@encryption/src/crypto/key-registration';
import { REQUEST_SIG_HEADER, readProofSubject, verifyRequestProof } from '@encryption/src/crypto/request-proof';
import { type VaultManifest, parseManifest, verifyManifest } from '@encryption/src/crypto/vault-manifest';
import { DEFAULT_KDF_PARAMS, verifyAuthPublicKeyBinding, verifyVaultChallenge } from '@encryption/src/crypto/vault-unlock';
import { prisma } from '@encryption/src/prisma/client';
import {
  type CompleteTxResult,
  activateRegistration,
  completeRegistrationInTx,
  completeResultToHttpError,
  isRetryableRegistrationError,
  loadAndVerifyPossession,
  mintIdentityInTx,
} from '@encryption/src/server/routes/registration-core';
import { addVaultListener, notifyVaultChanged, removeVaultListener } from '@encryption/src/server/vault-notify';
import { MAX_CONTINUITY_HOPS } from '@encryption/src/shared/constants';
import {
  API_ERROR_CONCURRENT_REGISTRATION,
  API_ERROR_RATE_LIMIT_APPROVALS,
  API_ERROR_VAULT_APPROVAL_NOT_FOUND,
  API_ERROR_VAULT_APPROVAL_NOT_READY,
  API_ERROR_VAULT_AUTH_BINDING_INVALID,
  API_ERROR_VAULT_CHALLENGE_EXPIRED,
  API_ERROR_VAULT_CHALLENGE_NOT_FOUND,
  API_ERROR_VAULT_ITEM_OUT_OF_DATE,
  API_ERROR_VAULT_KDF_PARAMS_INVALID,
  API_ERROR_VAULT_MANIFEST_INVALID,
  API_ERROR_VAULT_NOT_FOUND,
  API_ERROR_VAULT_PROOF_INVALID,
  API_ERROR_VAULT_REQUEST_SIGNATURE_INVALID,
} from '@encryption/src/shared/error-codes';
import {
  VaultApprovalApproveBodySchema,
  VaultApprovalRequestBodySchema,
  VaultFetchBodySchema,
  VaultKeyringSchema,
  VaultPutItemBodySchema,
  VaultStoreBodySchema,
} from '@encryption/src/shared/schemas/vault';

// KDF params are BOUNDED (not hard-pinned) on every keyring write: they must be at
// least the current standard (so no client can store a weak, cheap-to-brute-force
// vault) and no more than a sane maximum (so a stolen token can't store an
// absurd-cost vault that would DoS a later restore). Bounding rather than pinning
// lets the standard be RAISED over time for new vaults while OLDER vaults keep the
// (still-acceptable) params they were created with — restore uses each vault's OWN
// stored params (see /api/vault/meta -> kdf_variants), never a single constant.
const KDF_MAX_OPS = 10;
const KDF_MAX_MEM = 1024 * 1024 * 1024; // 1 GiB
const kdfParamsAllowed = (ops: number, mem: number) =>
  ops >= DEFAULT_KDF_PARAMS.opsLimit && ops <= KDF_MAX_OPS && mem >= DEFAULT_KDF_PARAMS.memLimit && mem <= KDF_MAX_MEM;

const CHALLENGE_TTL_SECONDS = 120;
const APPROVAL_TTL_SECONDS = 600;
// A device may only open a bounded number of pairing requests per window, so a
// stolen/replayed token can't flood the table or grind fingerprints.
const APPROVAL_RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;
const APPROVAL_RATE_LIMIT_MAX = 10;

// Fail-safe check that a keyring's auth verifier is bound to its identity:
// malformed base64 / key blobs are rejected (return false), never thrown.
async function authBindingValid(authPublicKeyB64: string, authPubSigB64: string, identityKeyBytes: Uint8Array): Promise<boolean> {
  try {
    return await verifyAuthPublicKeyBinding(
      base64ToUint8(authPublicKeyB64),
      base64ToUint8(authPubSigB64),
      importPublicKeyFromBytes(identityKeyBytes)
    );
  } catch {
    return false;
  }
}

// Fail-safe check that a manifest is signed by the vault's identity, so a stored
// vault is never left with a manifest the identity did not author (defends the
// integrity of the item index against a token-thief and DB tampering). Returns
// the parsed manifest on success (so the caller can check its revision), null on
// malformed JSON, a bad signature, or a signature that does not match the
// declared revision. Never throws.
async function verifiedManifest(
  manifestJson: string,
  manifestSigB64: string,
  identityKeyBytes: Uint8Array,
  expectedRevision: number
): Promise<VaultManifest | null> {
  const manifest = parseManifest(manifestJson);
  if (!manifest) return null;

  // The revision is inside the signed bytes, so binding it to the revision the
  // client asks the server to store stops an old, validly-signed manifest from
  // being paired with a different (e.g. higher) account revision.
  if (manifest.revision !== expectedRevision) return null;

  try {
    return (await verifyManifest(manifest, manifestSigB64, importPublicKeyFromBytes(identityKeyBytes))) ? manifest : null;
  } catch {
    return null;
  }
}

// Per-route auth tier (see architecture.md §7.1). Default (no flag) = JWT +
// identity signature (tier 2, interactive + sensitive).
// - SKIP_SIG: JWT only, no signature — cold prerequisites / PoP flows / the
//   lost-password disable, i.e. where the caller structurally cannot sign.
// - SIG_ONLY: identity signature only, NO JWT — the silent data-plane that must
//   run in the background (the vault holds the key, the interface/JWT may be
//   absent). `userId` comes from the signed `sub`.
const SKIP_SIG = { config: { skipRequestSignature: true } };
const SIG_ONLY = { config: { signatureOnly: true } };

// Grace window during which a SUPERSEDED (but not revoked) identity key may still
// authenticate a lagging device after a migration. Set to the same ~1 year as the
// superseded-vault content retention (§9), so the two windows reinforce each other.
const IDENTITY_AUTH_GRACE_MS = 365 * 24 * 60 * 60 * 1000;

export async function vaultRoute(app: FastifyInstance): Promise<void> {
  // The user's current vault: exactly one keyring has `disabledAt` null. The
  // sync and write paths operate on it; superseded (dormant) vaults are reachable
  // only through /fetch, which self-selects by the recovery phrase.
  const activeKeyring = (userId: string) => prisma.vaultKeyring.findFirst({ where: { userId, disabledAt: null } });

  // The user's ACTIVE identity WIRE public key (fast path: the overwhelmingly
  // common signer). Null if the user has no identity at all.
  async function activeIdentityWireKey(userId: string): Promise<Uint8Array | null> {
    const active = await prisma.identity.findFirst({ where: { userId, disabledAt: null }, orderBy: { generation: 'desc' } });

    return active ? new Uint8Array(active.signaturePublicKey) : null;
  }

  // Continuity-linked PREDECESSORS of the active identity that may still authenticate
  // a device lagging one (or a few) migrations behind. Walked back from the active
  // identity and consulted ONLY when the active-key check already failed, so the hot
  // path never runs this.
  //
  // A predecessor is accepted only when it clears BOTH bounds:
  //   - HOP: within MAX_CONTINUITY_HOPS of the active generation, verifying each
  //     link's cross-signature (`continuitySignature` on the newer node, signed by
  //     the older key over the newer identity's canonical bytes). This proves the
  //     older key really endorsed the newer one, so a forged predecessor — e.g. a
  //     malicious server injecting a key it controls — fails here.
  //   - TIME: `now - <when prev was superseded> < IDENTITY_AUTH_GRACE_MS`,
  //     ABSOLUTE and per-identity (never a chained "each migration within the
  //     window of the previous" test, which frequent migrations could walk back
  //     years). A predecessor's "superseded at" needs no column: it is exactly its
  //     SUCCESSOR's `createdAt` (the successor is minted at the moment the old
  //     identity is demoted), and while walking down we already hold that successor
  //     (`node`), so we compare `now - node.createdAt`. This caps cryptographic
  //     exposure: a retired key stops authenticating anything once its window
  //     closes. The window equals the superseded-vault content retention (§9), so
  //     past it the old vault is purged and a lagging device has nothing to sync.
  //
  // A DISABLED predecessor (`disabledAt` set = revoked) is never accepted; an
  // UNLINKED older generation (start-over / reset, no continuity signature) is a
  // trust break and is never reached (the walk needs a valid cross-signature to
  // step). Returns EMPTY today: nothing writes continuity links yet (the migration
  // flow is not wired), so `previousIdentityId` is always null and the loop never
  // runs — but the check is correct and ready the day it does. See architecture.md §7.1.
  async function continuityPredecessorWireKeys(userId: string, nowMs: number): Promise<Uint8Array[]> {
    let node = await prisma.identity.findFirst({ where: { userId, disabledAt: null }, orderBy: { generation: 'desc' } });
    const keys: Uint8Array[] = [];

    for (let hop = 0; node?.previousIdentityId && node.continuitySignature && hop < MAX_CONTINUITY_HOPS; hop++) {
      const successorCreatedAt = node.createdAt.getTime(); // = when `prev` was superseded
      const prev = await prisma.identity.findUnique({ where: { id: node.previousIdentityId } });
      if (!prev) break;

      const endorsed = await verifyIdentityContinuity(
        { userId: node.userId, generation: node.generation, algo: node.algo, signaturePublicKeyWire: new Uint8Array(node.signaturePublicKey) },
        uint8ToBase64(new Uint8Array(prev.signaturePublicKey)),
        uint8ToBase64(new Uint8Array(node.continuitySignature))
      );
      if (!endorsed) break; // broken / forged chain: stop, trust nothing further back

      // Out of window or revoked stops the walk: everything older was superseded
      // even earlier (against `now`), so it cannot be in-window either.
      if (prev.disabledAt !== null || nowMs - successorCreatedAt >= IDENTITY_AUTH_GRACE_MS) break;

      keys.push(new Uint8Array(prev.signaturePublicKey));
      node = prev;
    }

    return keys;
  }

  // Keep the RAW JSON body (still parsing it as usual) so the request-signature
  // middleware can verify the body digest against the exact bytes the client
  // signed, not a re-serialization. Scoped to the vault plugin only.
  app.addContentTypeParser('application/json', { parseAs: 'string' }, (request, body, done) => {
    (request as { rawBody?: string }).rawBody = body as string;

    if (body === '') return done(null, undefined);

    try {
      done(null, JSON.parse(body as string));
    } catch (err) {
      done(err as Error);
    }
  });

  // Verify the identity X-Signature on a request against `userId`: the active key
  // first (the common case), then a bounded walk of continuity-linked
  // predecessors. Shared by the signature-only and JWT+signature tiers.
  async function verifyIdentityRequest(request: FastifyRequest, userId: string, token: string, nowMs: number): Promise<boolean> {
    const proof = {
      token,
      method: request.method,
      path: request.url,
      userId,
      body: (request as { rawBody?: string }).rawBody ?? '',
      nowSeconds: Math.floor(nowMs / 1000),
    };

    const activeKey = await activeIdentityWireKey(userId);
    if (activeKey && (await verifyRequestProof({ ...proof, acceptableIdentityWireKeys: [activeKey] }))) return true;

    const predecessors = await continuityPredecessorWireKeys(userId, nowMs);

    return predecessors.length > 0 && verifyRequestProof({ ...proof, acceptableIdentityWireKeys: predecessors });
  }

  // Tiered, secure-by-default transport auth for EVERY vault route (§7.1):
  //  - SIG_ONLY -> identity signature ONLY, no JWT; userId comes from the signed
  //    sub (verified against that user's key, so a forged sub cannot pass).
  //  - SKIP_SIG -> JWT only.
  //  - default  -> JWT + identity signature, the signature's sub bound to the JWT.
  // A new route falls under the strictest default (JWT+sig) unless it opts out, so
  // forgetting fails loud (rejects a legitimate call), never silently open.
  app.addHook('preHandler', async (request, reply) => {
    const cfg = request.routeOptions.config as { skipRequestSignature?: boolean; signatureOnly?: boolean } | undefined;
    const token = request.headers[REQUEST_SIG_HEADER];
    const nowMs = Date.now();
    const reject = () => reply.status(401).send({ code: API_ERROR_VAULT_REQUEST_SIGNATURE_INVALID });

    if (cfg?.signatureOnly) {
      // Tier 1: no JWT. Read the claimed subject, verify the signature against
      // THAT user's identity, and only then adopt it as the authenticated user.
      if (typeof token !== 'string') return reject();

      const sub = await readProofSubject(token);
      if (!sub || !(await verifyIdentityRequest(request, sub, token, nowMs))) return reject();

      request.userId = sub;

      return;
    }

    await app.verifyJWT(request);

    if (cfg?.skipRequestSignature) return; // Tier 3/4: JWT only.

    // Tier 2: JWT + identity signature, which MUST name the same user — a valid
    // JWT for one account cannot be paired with another account's signature. Bound
    // two ways, both against `request.userId` (the JWT subject):
    //  1. the explicit check below: the signature's `sub` must equal the JWT user;
    //  2. `verifyIdentityRequest` resolves the key via `activeIdentityWireKey(
    //     request.userId)` and verifies the signature against the JWT user's OWN
    //     registered key, so a signature made with a different key cannot verify.
    if (typeof token !== 'string') return reject();
    if ((await readProofSubject(token)) !== request.userId) return reject();
    if (!(await verifyIdentityRequest(request, request.userId!, token, nowMs))) return reject();
  });

  // The KDF param variants a restoring client must try to derive the key from the
  // recovery phrase. Returns the DISTINCT (kdf_ops, kdf_mem) pairs across ALL of
  // the user's keyrings (any status: dormant vaults are restorable), so restore
  // uses each vault's OWN params — an older vault created before a params increase
  // keeps its original (still-acceptable) params and stays recoverable. Ascending
  // by cost so the client tries the cheapest (a normal, default-param vault) first.
  // Usually a single entry; more only after the standard was raised. Returns NO
  // language: the derivation hashes the phrase string (language-agnostic), and the
  // input validates against every wordlist. 404 when the account has no vault.
  app.get('/api/vault/meta', SKIP_SIG, async (request, reply) => {
    const keyrings = await prisma.vaultKeyring.findMany({ where: { userId: request.userId! }, select: { kdfOps: true, kdfMem: true } });

    if (keyrings.length === 0) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

    const seen = new Set<string>();
    const variants: Array<{ kdf_ops: number; kdf_mem: number }> = [];
    for (const k of keyrings) {
      const key = `${k.kdfOps}:${k.kdfMem}`;
      if (!seen.has(key)) {
        seen.add(key);
        variants.push({ kdf_ops: k.kdfOps, kdf_mem: k.kdfMem });
      }
    }
    variants.sort((a, b) => a.kdf_ops * a.kdf_mem - b.kdf_ops * b.kdf_mem);

    return { kdf_variants: variants };
  });

  // Cheap poll: the account revision an enrolled device compares before pulling.
  app.get('/api/vault/revision', SIG_ONLY, async (request) => {
    const keyring = await activeKeyring(request.userId!);
    const meta = keyring ? await prisma.vaultMeta.findUnique({ where: { vaultId: keyring.id } }) : null;

    return { revision: meta?.accountRevision ?? 0 };
  });

  // Server-push channel (SSE): a content-free "your vault changed" wake so a
  // user's OTHER devices pull near-instantly. SIG_ONLY: the stream is opened by
  // the vault iframe over the silent data plane, which holds an identity key but
  // no JWT, and it carries no vault data. See src/server/vault-notify.ts.
  app.get('/api/vault/events', SIG_ONLY, (request, reply) => {
    const userId = request.userId!;

    reply.hijack();
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no', // stop proxies buffering the stream
    });
    reply.raw.write(': connected\n\n');

    addVaultListener(userId, reply.raw);
    const heartbeat = setInterval(() => {
      try {
        reply.raw.write(': ping\n\n');
      } catch {
        /* dropped on the next notify */
      }
    }, 25000);
    heartbeat.unref(); // never let the keep-alive ping hold the process open

    request.raw.on('close', () => {
      clearInterval(heartbeat);
      removeVaultListener(userId, reply.raw);
    });
  });

  // Warm-sync pull: the sealed items + signed manifest + revision, WITHOUT the
  // wrappedVrk. An enrolled device already holds the VRK (cached under its
  // device key) and does not have the recovery phrase, so it cannot produce the
  // PoP that /fetch requires — and it does not need to: the items are sealed
  // under the random 256-bit VRK, so the identity signature (SIG_ONLY, proving
  // an open vault) is a sufficient gate here. Only the passphrase-brute-forceable
  // wrappedVrk stays behind the PoP gate on /fetch.
  app.get('/api/vault/items', SIG_ONLY, async (request, reply) => {
    const keyring = await activeKeyring(request.userId!);
    const meta = keyring ? await prisma.vaultMeta.findUnique({ where: { vaultId: keyring.id } }) : null;

    if (!keyring || !meta) return { revision: 0, manifest: null, manifest_sig: null, items: [] };

    const items = await prisma.vaultItem.findMany({ where: { vaultId: keyring.id } });

    return reply.send({
      revision: meta.accountRevision,
      manifest: meta.manifest,
      manifest_sig: uint8ToBase64(meta.manifestSig),
      items: items.map((i) => ({ item_id: i.itemId, type: i.type, ciphertext: i.ciphertext, revision_date_millis: i.revisionDate.getTime() })),
    });
  });

  // Issue a single-use nonce for a proof of possession of the recovery phrase.
  app.post('/api/vault/challenge', SKIP_SIG, async (request) => {
    // Opportunistic sweep of this user's expired challenges: they are otherwise
    // only deleted when re-presented, so an abandoned-challenge loop would grow
    // the table unbounded with no cron. Scoped to this user, cheap on the index.
    await prisma.vaultChallenge.deleteMany({ where: { userId: request.userId!, expiresAt: { lt: new Date() } } });

    const nonce = randomBytes(32);
    const challenge = await prisma.vaultChallenge.create({
      data: { userId: request.userId!, nonce, expiresAt: new Date(Date.now() + CHALLENGE_TTL_SECONDS * 1000) },
    });

    return { challenge_id: challenge.id, nonce: nonce.toString('base64') };
  });

  // The recovery phrase self-selects which of the user's vaults it unlocks: the
  // proof verifies against exactly the keyring whose authPublicKey it was derived
  // from, so a phrase can address a superseded (dormant) vault as well as the
  // current one. Shared by /fetch (read recovery) and /reactivate (make live).
  // Does NOT consume the challenge; the caller does, once it commits to its work.
  type Keyring = NonNullable<Awaited<ReturnType<typeof prisma.vaultKeyring.findFirst>>>;
  type ProofChallenge = NonNullable<Awaited<ReturnType<typeof prisma.vaultChallenge.findUnique>>>;
  type ProofResult = { ok: true; challenge: ProofChallenge; keyring: Keyring } | { ok: false; status: number; code: string };

  async function selectVaultByProof(userId: string, body: { challenge_id: string; proof: string }): Promise<ProofResult> {
    const challenge = await prisma.vaultChallenge.findUnique({ where: { id: body.challenge_id } });

    if (!challenge || challenge.userId !== userId) return { ok: false, status: 404, code: API_ERROR_VAULT_CHALLENGE_NOT_FOUND };

    if (challenge.expiresAt.getTime() < Date.now()) {
      await prisma.vaultChallenge.deleteMany({ where: { id: challenge.id } });

      return { ok: false, status: 410, code: API_ERROR_VAULT_CHALLENGE_EXPIRED };
    }

    const keyrings = await prisma.vaultKeyring.findMany({ where: { userId } });

    if (keyrings.length === 0) return { ok: false, status: 404, code: API_ERROR_VAULT_NOT_FOUND };

    const proof = base64ToUint8(body.proof);
    const nonce = new Uint8Array(challenge.nonce);

    for (const candidate of keyrings) {
      if (await verifyVaultChallenge(nonce, userId, proof, candidate.authPublicKey)) {
        return { ok: true, challenge, keyring: candidate };
      }
    }

    return { ok: false, status: 401, code: API_ERROR_VAULT_PROOF_INVALID };
  }

  // The releasable content of one vault: the wrapped VRK plus sealed items and
  // signed manifest. Shared by /fetch and /reactivate, both PoP-gated.
  async function loadVaultContent(keyring: Keyring) {
    const [meta, items] = await Promise.all([
      prisma.vaultMeta.findUnique({ where: { vaultId: keyring.id } }),
      prisma.vaultItem.findMany({ where: { vaultId: keyring.id } }),
    ]);

    return {
      vault_id: keyring.id,
      wrapped_vrk: keyring.wrappedVrk,
      revision: meta?.accountRevision ?? 0,
      manifest: meta?.manifest ?? null,
      manifest_sig: meta?.manifestSig ? uint8ToBase64(meta.manifestSig) : null,
      items: items.map((i) => ({ item_id: i.itemId, type: i.type, ciphertext: i.ciphertext, revision_date_millis: i.revisionDate.getTime() })),
    };
  }

  // PoP-gated fetch. Only here is the wrappedVrk released. The authPublicKey is
  // the server-side verifier and is never returned. `is_active` tells the client
  // whether the phrase resolved to the current vault or a dormant one, so it can
  // offer to reactivate the latter WITHOUT the client caching anything yet.
  app.post('/api/vault/fetch', SKIP_SIG, async (request, reply) => {
    const body = VaultFetchBodySchema.parse(request.body);

    const selected = await selectVaultByProof(request.userId!, body);
    if (!selected.ok) return reply.status(selected.status).send({ code: selected.code });

    const matched = selected.keyring;

    // Single-use: consume the challenge once it has done its job. deleteMany (not
    // delete) so a benign race with a concurrent consumer of the same challenge
    // resolves to a no-op instead of a P2025 that would surface as a 500.
    await prisma.vaultChallenge.deleteMany({ where: { id: selected.challenge.id } });

    return {
      ...(await loadVaultContent(matched)),
      is_active: matched.disabledAt === null,
      created_at_millis: matched.createdAt.getTime(),
    };
  });

  // Bring a dormant vault back as the current one. Same phrase PoP as /fetch, so
  // it is an explicit, authenticated switch. Reactivation is only ever flag
  // flips: the recovered vault's keyring and its directory identity + encryption
  // key are (re)enabled, and whichever vault was active is demoted to dormant
  // (kept, still recoverable by its own phrase). Because it demotes the current
  // vault, the caller confirms with the user first.
  app.post('/api/vault/reactivate', SKIP_SIG, async (request, reply) => {
    const body = VaultFetchBodySchema.parse(request.body);
    const userId = request.userId!;

    const selected = await selectVaultByProof(userId, body);
    if (!selected.ok) return reply.status(selected.status).send({ code: selected.code });

    const target = selected.keyring;

    await prisma.vaultChallenge.deleteMany({ where: { id: selected.challenge.id } });

    // Already the current vault: nothing to switch, but still release the content
    // so the caller can cache it in the one path it caches at all.
    if (target.disabledAt === null)
      return { reactivated: false, active_vault_id: target.id, disabled_vault_id: null, ...(await loadVaultContent(target)) };

    // The vault we are about to demote, so the client can name it to the user.
    const previouslyActive = await activeKeyring(userId);

    // Serializable + retry, like the bootstrap and standalone registration routes:
    // this flips the single active identity/encryption-key/keyring per user, so it
    // must not interleave with a concurrent bootstrap or /register on the same user
    // (READ COMMITTED could leave two active keyrings, or an active keyring pointing
    // at a demoted identity).
    try {
      await prisma.$transaction(
        async (tx) => {
          // Re-point the directory to this vault's identity + its latest encryption
          // key, disabling whatever pair was active (same helper the registration
          // flow uses to keep exactly one active pair per user).
          const encKey = await tx.encryptionKey.findFirst({ where: { identityId: target.identityId }, orderBy: { version: 'desc' } });
          if (encKey) await activateRegistration(tx, userId, encKey.id, target.identityId);

          // Flip the vaults: demote every currently active keyring, promote this one.
          await tx.vaultKeyring.updateMany({ where: { userId, disabledAt: null }, data: { disabledAt: new Date() } });
          await tx.vaultKeyring.update({ where: { id: target.id }, data: { disabledAt: null } });
        },
        { isolationLevel: 'Serializable' }
      );
    } catch (err) {
      if (isRetryableRegistrationError(err)) return reply.status(409).send({ code: API_ERROR_CONCURRENT_REGISTRATION });
      throw err;
    }

    // Release the (now current) vault so the client caches it in the same step
    // that committed the switch: nothing is persisted locally before this point.
    return {
      reactivated: true,
      active_vault_id: target.id,
      disabled_vault_id: previouslyActive?.id ?? null,
      disabled_vault_created_at_millis: previouslyActive?.createdAt.getTime() ?? null,
      ...(await loadVaultContent(target)),
    };
  });

  // Atomic onboarding / start over: the directory registration (keys) AND the
  // vault (keyring + every item + the signed manifest) commit in ONE transaction,
  // so onboarding can never leave keys registered without a recoverable vault, or
  // a vault whose keys never made it to the directory.
  //
  // Starting over NEVER destroys the previous vault. If the user already has an
  // active vault, its keyring is marked dormant (disabledAt set) and a brand-new
  // active vault is created alongside it. The dormant vault's sealed content is
  // preserved so its own recovery phrase can still recover it within the
  // retention window (see /fetch, which self-selects a vault by its phrase).
  app.post('/api/vault', SKIP_SIG, async (request, reply) => {
    const body = VaultStoreBodySchema.parse(request.body);
    const userId = request.userId!;

    // Cheap input check before the proof: the keyring's KDF params must be the
    // pinned standard (uniform params keep restore correct for any vault; also
    // blocks a weak-params vault).
    if (!kdfParamsAllowed(body.keyring.kdf_ops, body.keyring.kdf_mem)) return reply.status(400).send({ code: API_ERROR_VAULT_KDF_PARAMS_INVALID });

    // Read-only proof of possession of both private keys, before any write.
    const check = await loadAndVerifyPossession(userId, body.registration);
    if (!check.ok) return reply.status(check.status).send({ code: check.code });

    // The keyring's auth verifier must be bound to the identity being registered,
    // so a token-thief can't write a keyring with a verifier they control (which
    // would let them pass the unlock PoP gate and pull the brute-forceable VRK).
    if (!(await authBindingValid(body.keyring.auth_public_key, body.keyring.auth_pub_sig, check.challenge.signaturePublicKey)))
      return reply.status(400).send({ code: API_ERROR_VAULT_AUTH_BINDING_INVALID });

    // The manifest must be signed by the same identity, so the stored vault's item
    // index is always authentic (not forgeable by a token-thief or DB tampering).
    // A freshly bootstrapped vault is account revision 1, so the signed manifest
    // must declare that revision.
    if (!(await verifiedManifest(body.manifest, body.manifest_sig, check.challenge.signaturePublicKey, 1)))
      return reply.status(400).send({ code: API_ERROR_VAULT_MANIFEST_INVALID });

    // Serializable + retry, matching the standalone registration route: the
    // registration writes run first, then the vault writes, all-or-nothing.
    let result: CompleteTxResult;

    try {
      result = await prisma.$transaction(
        async (tx): Promise<CompleteTxResult> => {
          // Bootstrap is the SOLE identity minter: create (or re-enable) the
          // identity first, then register the encryption key under it and create
          // the vault keyring below, all atomically. completeRegistrationInTx
          // itself never mints, so it can't be used to register keys with no vault.
          const minted = await mintIdentityInTx(tx, userId, check.challenge.signaturePublicKey);
          if (minted.kind !== 'ok') return minted;

          const reg = await completeRegistrationInTx(tx, userId, check.challenge);
          if (reg.kind !== 'success') return reg;

          // Supersede the current vault (if any) instead of deleting it: mark its
          // keyring dormant so it stops being the sync target but its content
          // survives for phrase recovery. This keeps the invariant that at most
          // one keyring per user is active.
          await tx.vaultKeyring.updateMany({ where: { userId, disabledAt: null }, data: { disabledAt: new Date() } });

          const keyring = await tx.vaultKeyring.create({
            data: {
              userId,
              identityId: reg.identityId,
              wrappedVrk: body.keyring.wrapped_vrk,
              authPublicKey: Buffer.from(base64ToUint8(body.keyring.auth_public_key)),
              authPubSig: Buffer.from(base64ToUint8(body.keyring.auth_pub_sig)),
              kdfOps: body.keyring.kdf_ops,
              kdfMem: body.keyring.kdf_mem,
              lang: body.keyring.lang,
            },
          });
          await tx.vaultItem.createMany({
            data: body.items.map((i) => ({
              vaultId: keyring.id,
              itemId: i.item_id,
              type: i.type,
              ciphertext: i.ciphertext,
              revisionDate: new Date(i.revision_date_millis),
            })),
          });
          await tx.vaultMeta.create({
            data: { vaultId: keyring.id, accountRevision: 1, manifest: body.manifest, manifestSig: Buffer.from(base64ToUint8(body.manifest_sig)) },
          });

          return reg;
        },
        { isolationLevel: 'Serializable' }
      );
    } catch (err) {
      if (isRetryableRegistrationError(err)) return reply.status(409).send({ code: API_ERROR_CONCURRENT_REGISTRATION });
      throw err;
    }

    if (result.kind !== 'success') {
      const mapped = completeResultToHttpError(result)!;

      return reply.status(mapped.status).send(mapped.params ? { code: mapped.code, params: mapped.params } : { code: mapped.code });
    }

    return { revision: 1 };
  });

  // Write-through item update with per-item optimistic concurrency. The client
  // sends the freshly signed manifest with every write, since any item change
  // changes the manifest.
  app.put<{ Params: { itemId: string } }>('/api/vault/items/:itemId', SIG_ONLY, async (request, reply) => {
    const body = VaultPutItemBodySchema.parse(request.body);
    const userId = request.userId!;

    if (body.item.item_id !== request.params.itemId) return reply.status(400).send({ code: API_ERROR_VAULT_ITEM_OUT_OF_DATE });

    const keyring = await activeKeyring(userId);
    if (!keyring) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });
    const vaultId = keyring.id;

    // The re-signed manifest that accompanies every item write must verify against
    // the vault's identity, so a mutation can never store an unauthentic index.
    // It must also declare the exact revision this write commits to.
    const identity = await prisma.identity.findUnique({ where: { id: keyring.identityId } });
    if (!identity) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

    if (!(await verifiedManifest(body.manifest, body.manifest_sig, identity.signaturePublicKey, body.revision)))
      return reply.status(400).send({ code: API_ERROR_VAULT_MANIFEST_INVALID });

    const result = await prisma.$transaction(async (tx) => {
      const current = await tx.vaultItem.findUnique({ where: { vaultId_itemId: { vaultId, itemId: body.item.item_id } } });

      if (current) {
        // Reject a stale write on this item: the client must have last seen the
        // exact revisionDate the server holds. An echo of the server's own value
        // round-trips losslessly, so there is no clock skew to tolerate; anything
        // else (older, newer, or absent) means the client did not see this item's
        // current state and must re-pull and merge.
        if (body.last_known_revision_date_millis !== current.revisionDate.getTime()) {
          return { conflict: true as const };
        }
      }

      // Account-level compare-and-set: this write must advance the revision by
      // exactly one from what is stored. Two devices that both branch from the
      // same revision therefore cannot both commit; the loser gets a 409, re-pulls,
      // re-merges, and pushes a manifest that covers the other device's item. This
      // is what stops a concurrent pair of different-item writes from leaving the
      // stored items and the surviving manifest permanently incoherent.
      //
      // The CAS is expressed as a single conditional updateMany, NOT a findUnique
      // check followed by an unconditional update: this transaction runs at
      // Postgres default READ COMMITTED, so a read-then-write would let two racers
      // both observe revision-1, both pass, and the second silently clobber the
      // first. updateMany filters on the expected revision inside the write, so the
      // loser matches 0 rows and the manifest never diverges from the item set.
      const advanced = await tx.vaultMeta.updateMany({
        where: { vaultId, accountRevision: body.revision - 1 },
        data: { accountRevision: body.revision, manifest: body.manifest, manifestSig: Buffer.from(base64ToUint8(body.manifest_sig)) },
      });

      if (advanced.count === 0) {
        return { conflict: true as const };
      }

      await tx.vaultItem.upsert({
        where: { vaultId_itemId: { vaultId, itemId: body.item.item_id } },
        create: {
          vaultId,
          itemId: body.item.item_id,
          type: body.item.type,
          ciphertext: body.item.ciphertext,
          revisionDate: new Date(body.item.revision_date_millis),
        },
        update: { type: body.item.type, ciphertext: body.item.ciphertext, revisionDate: new Date(body.item.revision_date_millis) },
      });

      return { conflict: false as const, revision: body.revision };
    });

    if (result.conflict) return reply.status(409).send({ code: API_ERROR_VAULT_ITEM_OUT_OF_DATE });

    // Wake this user's other devices so they pull the change (write-through +
    // server-push together give near-instant cross-device convergence).
    notifyVaultChanged(userId, result.revision);

    return { revision: result.revision };
  });

  // Change the recovery phrase: re-wrap only. The vault items are untouched.
  app.put('/api/vault/keyring', async (request, reply) => {
    const body = VaultKeyringSchema.parse(request.body);
    const userId = request.userId!;

    const existing = await activeKeyring(userId);
    if (!existing) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

    if (!kdfParamsAllowed(body.kdf_ops, body.kdf_mem)) return reply.status(400).send({ code: API_ERROR_VAULT_KDF_PARAMS_INVALID });

    // Same binding check as bootstrap: the new auth verifier must be signed by
    // this vault's identity, so a token-thief can't swap in one they control.
    const identity = await prisma.identity.findUnique({ where: { id: existing.identityId } });
    if (!identity) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

    if (!(await authBindingValid(body.auth_public_key, body.auth_pub_sig, identity.signaturePublicKey)))
      return reply.status(400).send({ code: API_ERROR_VAULT_AUTH_BINDING_INVALID });

    await prisma.vaultKeyring.update({
      where: { id: existing.id },
      data: {
        wrappedVrk: body.wrapped_vrk,
        authPublicKey: Buffer.from(base64ToUint8(body.auth_public_key)),
        authPubSig: Buffer.from(base64ToUint8(body.auth_pub_sig)),
        kdfOps: body.kdf_ops,
        kdfMem: body.kdf_mem,
        lang: body.lang,
      },
    });

    return { updated: true };
  });

  // ----- Device approval (QR enrollment) -------------------------------------

  // Load an approval that the caller owns AND that has not expired. An expired
  // row is deleted and treated as absent, so the TTL is enforced on every path
  // that can release the VRK (not just the pending listing) and stale rows can't
  // linger to be approved or collected long after the pairing window closed.
  async function loadOwnedApproval(requestId: string, userId: string) {
    const approval = await prisma.vaultApproval.findUnique({ where: { requestId } });

    if (!approval || approval.userId !== userId) return null;

    if (approval.expiresAt.getTime() < Date.now()) {
      await prisma.vaultApproval.deleteMany({ where: { requestId } });

      return null;
    }

    return approval;
  }

  app.post('/api/vault/approvals/request', SKIP_SIG, async (request, reply) => {
    const body = VaultApprovalRequestBodySchema.parse(request.body);
    const userId = request.userId!;

    const now = Date.now();

    // Opportunistic cleanup, but ONLY of rows already outside the rate-limit
    // window, so abandoned requests don't accumulate without a cron. Expired-but-
    // recent rows are deliberately kept: they can never be collected (an expired
    // approval is rejected by loadOwnedApproval), yet they must still count toward
    // the limit. Deleting every expired row here (TTL is 10 min, window is 1 hour)
    // would let a token grind ~6x the intended rate by waiting out the TTL.
    await prisma.vaultApproval.deleteMany({
      where: { userId, expiresAt: { lt: new Date(now) }, createdAt: { lt: new Date(now - APPROVAL_RATE_LIMIT_WINDOW_MS) } },
    });

    // Bound how many pairing requests a device can open per window.
    const recent = await prisma.vaultApproval.count({
      where: { userId, createdAt: { gte: new Date(now - APPROVAL_RATE_LIMIT_WINDOW_MS) } },
    });

    if (recent >= APPROVAL_RATE_LIMIT_MAX) {
      return reply.status(429).send({ code: API_ERROR_RATE_LIMIT_APPROVALS });
    }

    const approval = await prisma.vaultApproval.create({
      data: {
        userId,
        requestId: randomUUID(),
        devicePublicKey: body.device_public_key,
        expiresAt: new Date(Date.now() + APPROVAL_TTL_SECONDS * 1000),
      },
    });

    return { request_id: approval.requestId, device_public_key: approval.devicePublicKey };
  });

  app.post<{ Params: { requestId: string } }>('/api/vault/approvals/:requestId/approve', async (request, reply) => {
    const body = VaultApprovalApproveBodySchema.parse(request.body);
    const approval = await loadOwnedApproval(request.params.requestId, request.userId!);

    // Only the owner can approve their own pending, unexpired device.
    if (!approval) return reply.status(404).send({ code: API_ERROR_VAULT_APPROVAL_NOT_FOUND });

    await prisma.vaultApproval.update({ where: { requestId: approval.requestId }, data: { wrappedDeviceBootstrap: body.wrapped_device_bootstrap } });

    return { approved: true };
  });

  app.get<{ Params: { requestId: string } }>('/api/vault/approvals/:requestId', SKIP_SIG, async (request, reply) => {
    const approval = await loadOwnedApproval(request.params.requestId, request.userId!);

    if (!approval) return reply.status(404).send({ code: API_ERROR_VAULT_APPROVAL_NOT_FOUND });

    if (!approval.wrappedDeviceBootstrap) return reply.status(425).send({ code: API_ERROR_VAULT_APPROVAL_NOT_READY });

    // One-shot: consume once collected.
    await prisma.vaultApproval.delete({ where: { requestId: approval.requestId } });

    return { wrapped_device_bootstrap: approval.wrappedDeviceBootstrap, device_public_key: approval.devicePublicKey };
  });

  // Enrolled device, no-camera fallback: list this user's pending (not-yet-approved,
  // unexpired) requests so the manual decimal-fingerprint path can find the right
  // key without the user having to type the requestId. Owner-scoped. Static route,
  // so it takes precedence over `/approvals/:requestId`.
  app.get('/api/vault/approvals/pending', async (request) => {
    const pending = await prisma.vaultApproval.findMany({
      where: { userId: request.userId!, wrappedDeviceBootstrap: null, expiresAt: { gt: new Date() } },
      select: { requestId: true, devicePublicKey: true },
    });

    return { approvals: pending.map((a) => ({ request_id: a.requestId, device_public_key: a.devicePublicKey })) };
  });
}
