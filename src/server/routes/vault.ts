import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { randomBytes, randomUUID } from 'node:crypto';
import { z } from 'zod';

import { base64ToUint8, importPublicKeyFromBytes, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { type VaultManifest, parseManifest, verifyManifest } from '@encryption/src/crypto/vault-manifest';
import { DEFAULT_KDF_PARAMS, verifyAuthPublicKeyBinding, verifyVaultChallenge } from '@encryption/src/crypto/vault-unlock';
import { prisma } from '@encryption/src/prisma/client';
import { errorResponses } from '@encryption/src/server/error-response';
import { emergencyApprovalHolds, notifyVaultRecovered, verifyEscrowSubmission } from '@encryption/src/server/routes/emergency-core';
import {
  type CompleteTxResult,
  activateRegistration,
  completeRegistrationInTx,
  completeResultToHttpError,
  isRetryableRegistrationError,
  loadAndVerifyPossession,
  mintIdentityInTx,
} from '@encryption/src/server/routes/registration-core';
import { SIG_ONLY, SKIP_SIG, assertUserId, registerTransportAuth } from '@encryption/src/server/routes/transport-auth';
import { CompleteKeyPossessionBodySchema } from '@encryption/src/server/schemas/key-possession';
import { addVaultListener, notifyVaultChanged, removeVaultListener } from '@encryption/src/server/vault-notify';
import { configureZodValidation } from '@encryption/src/server/zod-validation';
import {
  API_ERROR_CONCURRENT_REGISTRATION,
  API_ERROR_EMERGENCY_ESCROW_INVALID,
  API_ERROR_EMERGENCY_REARM_REQUIRED,
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
} from '@encryption/src/shared/error-codes';
import { VaultKeyringUpdateBodySchema } from '@encryption/src/shared/schemas/emergency-access';
import { VaultItemSchema, VaultKeyringSchema } from '@encryption/src/shared/schemas/vault';

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

// ----- Request body schemas --------------------------------------------------

const MAX_KEY_B64 = 1024; // Ed25519 key / signature blob
const MAX_WRAPPED_VRK_B64 = 4096; // wrapped vault root key
const MAX_DEVICE_KEY_B64 = 4096; // device public key blob
const MAX_MANIFEST = 128 * 1024; // signed item-index manifest (JSON)

// PoP-gated fetch: the client presents the challenge it was issued plus a
// signature over it by the vault auth key.
const VaultFetchBodySchema = z.object({
  challenge_id: z.string().min(1).max(256),
  proof: z.string().min(1).max(MAX_KEY_B64), // base64 Ed25519 over the challenge nonce
});

// ----- Response schemas ------------------------------------------------------

const VaultContentSchema = z.object({
  vault_id: z.string(),
  wrapped_vrk: z.string(),
  credential_type: z.enum(['primary', 'emergency']),
  revision: z.number().int().nonnegative(),
  manifest: z.string().nullable(),
  manifest_sig: z.string().nullable(),
  items: z.array(VaultItemSchema),
});

const VaultRevisionOnlyResponseSchema = z.object({ revision: z.number().int().positive() });

const RequestIdParamsSchema = z.object({ requestId: z.string() });

export async function vaultRoute(app: FastifyInstance): Promise<void> {
  configureZodValidation(app);
  registerTransportAuth(app);
  // The user's current vault: exactly one keyring has `disabledAt` null. The
  // sync and write paths operate on it; superseded (dormant) vaults are reachable
  // only through /fetch, which self-selects by the recovery phrase.
  const activeKeyring = (userId: string) => prisma.vaultKeyring.findFirst({ where: { userId, disabledAt: null } });

  // Every keyslot the caller may currently open: their own primary credential
  // always, plus an emergency credential only while its approval actually holds
  // (accepted, requested, waited out, not revoked). An escrow whose approval
  // lapsed is therefore unopenable without deleting anything.
  async function unlockableCredentials(userId: string, nowMs: number) {
    const credentials = await prisma.vaultCredential.findMany({ where: { vault: { userId } }, include: { vault: true, emergencyAccess: true } });

    return credentials.filter((c) => (c.type === 'primary' ? true : c.emergencyAccess !== null && emergencyApprovalHolds(c.emergencyAccess, nowMs)));
  }

  type Credential = Awaited<ReturnType<typeof unlockableCredentials>>[number];

  // The KDF param variants a restoring client must try to derive the key from the
  // recovery phrase. Returns the DISTINCT (kdf_ops, kdf_mem) pairs across ALL of
  // the user's keyrings (any status: dormant vaults are restorable), so restore
  // uses each vault's OWN params — an older vault created before a params increase
  // keeps its original (still-acceptable) params and stays recoverable. Ascending
  // by cost so the client tries the cheapest (a normal, default-param vault) first.
  // Usually a single entry; more only after the standard was raised. Returns NO
  // language: the derivation hashes the phrase string (language-agnostic), and the
  // input validates against every wordlist. 404 when the account has no vault.
  app.withTypeProvider<ZodTypeProvider>().get('/api/vault/meta', {
    ...SKIP_SIG,
    schema: {
      response: {
        200: z.object({
          kdf_variants: z.array(z.object({ kdf_ops: z.number().int().positive(), kdf_mem: z.number().int().positive() })),
        }),
        ...errorResponses(404),
      },
    },
    handler: async (request, reply) => {
      assertUserId(request);
      const credentials = await unlockableCredentials(request.userId, Date.now());

      if (credentials.length === 0) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

      const seen = new Set<string>();
      const variants: Array<{ kdf_ops: number; kdf_mem: number }> = [];
      for (const c of credentials) {
        const key = `${c.kdfOps}:${c.kdfMem}`;
        if (!seen.has(key)) {
          seen.add(key);
          variants.push({ kdf_ops: c.kdfOps, kdf_mem: c.kdfMem });
        }
      }
      variants.sort((a, b) => a.kdf_ops * a.kdf_mem - b.kdf_ops * b.kdf_mem);

      return { kdf_variants: variants };
    },
  });

  // Cheap poll: the account revision an enrolled device compares before pulling.
  app.withTypeProvider<ZodTypeProvider>().get('/api/vault/revision', {
    ...SIG_ONLY,
    schema: { response: { 200: z.object({ revision: z.number().int().nonnegative() }) } },
    handler: async (request) => {
      assertUserId(request);
      const keyring = await activeKeyring(request.userId);
      const meta = keyring ? await prisma.vaultMeta.findUnique({ where: { vaultId: keyring.id } }) : null;

      return { revision: meta?.accountRevision ?? 0 };
    },
  });

  // Server-push channel (SSE): a content-free "your vault changed" wake so a
  // user's OTHER devices pull near-instantly. SIG_ONLY: the stream is opened by
  // the vault iframe over the silent data plane, which holds an identity key but
  // no JWT, and it carries no vault data. See src/server/vault-notify.ts.
  app.get('/api/vault/events', { ...SIG_ONLY, schema: { hide: true } }, (request, reply) => {
    assertUserId(request);
    const userId = request.userId;

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
  app.withTypeProvider<ZodTypeProvider>().get('/api/vault/items', {
    ...SIG_ONLY,
    schema: {
      response: {
        200: z.object({
          revision: z.number().int().nonnegative(),
          manifest: z.string().nullable(),
          manifest_sig: z.string().nullable(),
          items: z.array(VaultItemSchema),
        }),
      },
    },
    handler: async (request, reply) => {
      assertUserId(request);
      const keyring = await activeKeyring(request.userId);
      const meta = keyring ? await prisma.vaultMeta.findUnique({ where: { vaultId: keyring.id } }) : null;

      if (!keyring || !meta) return { revision: 0, manifest: null, manifest_sig: null, items: [] };

      const items = await prisma.vaultItem.findMany({ where: { vaultId: keyring.id } });

      return reply.send({
        revision: meta.accountRevision,
        manifest: meta.manifest,
        manifest_sig: uint8ToBase64(meta.manifestSig),
        items: items.map((i) => ({ item_id: i.itemId, type: i.type, ciphertext: i.ciphertext, revision_date_millis: i.revisionDate.getTime() })),
      });
    },
  });

  // Issue a single-use nonce for a proof of possession of the recovery phrase.
  app.withTypeProvider<ZodTypeProvider>().post('/api/vault/challenge', {
    ...SKIP_SIG,
    schema: { response: { 200: z.object({ challenge_id: z.string(), nonce: z.string() }) } },
    handler: async (request) => {
      assertUserId(request);
      // Opportunistic sweep of this user's expired challenges: they are otherwise
      // only deleted when re-presented, so an abandoned-challenge loop would grow
      // the table unbounded with no cron. Scoped to this user, cheap on the index.
      await prisma.vaultChallenge.deleteMany({ where: { userId: request.userId, expiresAt: { lt: new Date() } } });

      const nonce = randomBytes(32);
      const challenge = await prisma.vaultChallenge.create({
        data: { userId: request.userId, nonce, expiresAt: new Date(Date.now() + CHALLENGE_TTL_SECONDS * 1000) },
      });

      return { challenge_id: challenge.id, nonce: nonce.toString('base64') };
    },
  });

  // The recovery phrase self-selects which of the user's vaults it unlocks: the
  // proof verifies against exactly the keyring whose authPublicKey it was derived
  // from, so a phrase can address a superseded (dormant) vault as well as the
  // current one. Shared by /fetch (read recovery) and /reactivate (make live).
  // Does NOT consume the challenge; the caller does, once it commits to its work.
  type Keyring = NonNullable<Awaited<ReturnType<typeof prisma.vaultKeyring.findFirst>>>;
  type ProofChallenge = NonNullable<Awaited<ReturnType<typeof prisma.vaultChallenge.findUnique>>>;
  // The failure statuses are a precise union rather than `number` so the routes
  // forwarding them still satisfy the statuses declared in their own schema.
  type ProofResult =
    | { ok: true; challenge: ProofChallenge; credential: Credential; keyring: Keyring }
    | { ok: false; status: 401 | 404 | 410; code: string };

  async function selectVaultByProof(userId: string, body: { challenge_id: string; proof: string }): Promise<ProofResult> {
    const challenge = await prisma.vaultChallenge.findUnique({ where: { id: body.challenge_id } });

    if (!challenge || challenge.userId !== userId) return { ok: false, status: 404, code: API_ERROR_VAULT_CHALLENGE_NOT_FOUND };

    if (challenge.expiresAt.getTime() < Date.now()) {
      await prisma.vaultChallenge.deleteMany({ where: { id: challenge.id } });

      return { ok: false, status: 410, code: API_ERROR_VAULT_CHALLENGE_EXPIRED };
    }

    const candidates = await unlockableCredentials(userId, Date.now());

    if (candidates.length === 0) return { ok: false, status: 404, code: API_ERROR_VAULT_NOT_FOUND };

    const proof = base64ToUint8(body.proof);
    const nonce = new Uint8Array(challenge.nonce);

    for (const candidate of candidates) {
      if (await verifyVaultChallenge(nonce, userId, proof, candidate.authPublicKey)) {
        return { ok: true, challenge, credential: candidate, keyring: candidate.vault };
      }
    }

    return { ok: false, status: 401, code: API_ERROR_VAULT_PROOF_INVALID };
  }

  // The releasable content of one vault: the wrapped VRK plus sealed items and
  // signed manifest. Shared by /fetch and /reactivate, both PoP-gated.
  async function loadVaultContent(credential: Credential) {
    const keyring = credential.vault;
    const [meta, items] = await Promise.all([
      prisma.vaultMeta.findUnique({ where: { vaultId: keyring.id } }),
      prisma.vaultItem.findMany({ where: { vaultId: keyring.id } }),
    ]);

    return {
      vault_id: keyring.id,
      wrapped_vrk: credential.wrappedVrk,
      credential_type: credential.type,
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
  app.withTypeProvider<ZodTypeProvider>().post('/api/vault/fetch', {
    ...SKIP_SIG,
    schema: {
      body: VaultFetchBodySchema,
      response: {
        200: VaultContentSchema.extend({
          is_active: z.boolean(),
          created_at_millis: z.number().int().nonnegative(),
        }),
        ...errorResponses(400, 401, 404, 410),
      },
    },
    handler: async (request, reply) => {
      assertUserId(request);
      const body = request.body;

      const selected = await selectVaultByProof(request.userId, body);
      if (!selected.ok) return reply.status(selected.status).send({ code: selected.code });

      const matched = selected.keyring;

      // Single-use: consume the challenge once it has done its job. deleteMany (not
      // delete) so a benign race with a concurrent consumer of the same challenge
      // resolves to a no-op instead of a P2025 that would surface as a 500.
      await prisma.vaultChallenge.deleteMany({ where: { id: selected.challenge.id } });

      return {
        ...(await loadVaultContent(selected.credential)),
        is_active: matched.disabledAt === null,
        created_at_millis: matched.createdAt.getTime(),
      };
    },
  });

  // Bring a dormant vault back as the current one. Same phrase PoP as /fetch, so
  // it is an explicit, authenticated switch. Reactivation is only ever flag
  // flips: the recovered vault's keyring and its directory identity + encryption
  // key are (re)enabled, and whichever vault was active is demoted to dormant
  // (kept, still recoverable by its own phrase). Because it demotes the current
  // vault, the caller confirms with the user first.
  app.withTypeProvider<ZodTypeProvider>().post('/api/vault/reactivate', {
    ...SKIP_SIG,
    schema: {
      body: VaultFetchBodySchema,
      response: {
        200: VaultContentSchema.extend({
          reactivated: z.boolean(),
          active_vault_id: z.string(),
          disabled_vault_id: z.string().nullable(),
          disabled_vault_created_at_millis: z.number().int().nonnegative().nullable(),
        }),
        ...errorResponses(400, 401, 404, 409, 410),
      },
    },
    handler: async (request, reply) => {
      const body = request.body;
      assertUserId(request);
      const userId = request.userId;

      const selected = await selectVaultByProof(userId, body);
      if (!selected.ok) return reply.status(selected.status).send({ code: selected.code });

      const target = selected.keyring;

      await prisma.vaultChallenge.deleteMany({ where: { id: selected.challenge.id } });

      // Already the current vault: nothing to switch, but still release the content
      // so the caller can cache it in the one path it caches at all.
      if (target.disabledAt === null)
        return {
          reactivated: false,
          active_vault_id: target.id,
          disabled_vault_id: null,
          disabled_vault_created_at_millis: null,
          ...(await loadVaultContent(selected.credential)),
        };

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
        ...(await loadVaultContent(selected.credential)),
      };
    },
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
  app.withTypeProvider<ZodTypeProvider>().post('/api/vault', {
    ...SKIP_SIG,
    schema: {
      // Atomic onboarding body: the directory registration (proof of possession) folded
      body:
        // together with the vault (keyring + sealed items + signed manifest), so both
        // commit in one server transaction. Server-only: nothing outside this route enforces it,
        // and the UI reads its type off the generated client.
        z.object({
          registration: CompleteKeyPossessionBodySchema,
          keyring: VaultKeyringSchema,
          items: z.array(VaultItemSchema).min(1).max(1024),
          manifest: z.string().min(1).max(MAX_MANIFEST),
          manifest_sig: z.string().min(1).max(MAX_KEY_B64),
        }),
      response: { 200: VaultRevisionOnlyResponseSchema, ...errorResponses(400, 403, 404, 409, 410, 429) },
    },
    handler: async (request, reply) => {
      const body = request.body;
      assertUserId(request);
      const userId = request.userId;

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
                credentials: {
                  create: {
                    type: 'primary',
                    wrappedVrk: body.keyring.wrapped_vrk,
                    authPublicKey: Buffer.from(base64ToUint8(body.keyring.auth_public_key)),
                    authPubSig: Buffer.from(base64ToUint8(body.keyring.auth_pub_sig)),
                    kdfOps: body.keyring.kdf_ops,
                    kdfMem: body.keyring.kdf_mem,
                    lang: body.keyring.lang,
                  },
                },
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
    },
  });

  // Write-through item update with per-item optimistic concurrency. The client
  // sends the freshly signed manifest with every write, since any item change
  // changes the manifest.
  app.withTypeProvider<ZodTypeProvider>().put('/api/vault/items/:itemId', {
    ...SIG_ONLY,
    schema: {
      params: z.object({ itemId: z.string() }),
      // A single item write, carrying the last revision the client saw for optimistic
      body:
        // concurrency. `null` means the client believes the item is new.
        z.object({
          item: VaultItemSchema,
          last_known_revision_date_millis: z.number().int().nonnegative().nullable(),
          manifest: z.string().min(1).max(MAX_MANIFEST),
          manifest_sig: z.string().min(1).max(MAX_KEY_B64),
          revision: z.number().int().positive(), // the manifest revision; becomes the account revision
        }),
      response: { 200: VaultRevisionOnlyResponseSchema, ...errorResponses(400, 404, 409) },
    },
    handler: async (request, reply) => {
      const body = request.body;
      assertUserId(request);
      const userId = request.userId;

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
    },
  });

  // Change the recovery phrase: re-wrap only, the vault items are untouched.
  // When a trusted contact's recovery is currently GRANTED, this write must
  // atomically burn + re-arm every granted escrow: the contact has (or may have)
  // seen an emergency phrase, and a phrase change is exactly the moment that burns
  // it, so the server refuses to let the rotation commit without a replacement
  // escrow per granted relationship (a partial rotation would leave a revealed
  // phrase alive, or strip the user of their recovery contacts).
  app.withTypeProvider<ZodTypeProvider>().put('/api/vault/keyring', {
    schema: {
      body: VaultKeyringUpdateBodySchema,
      response: { 200: z.object({ updated: z.boolean(), rearmed: z.number().int().nonnegative() }), ...errorResponses(400, 404, 409) },
    },
    handler: async (request, reply) => {
      const body = request.body;
      assertUserId(request);
      const userId = request.userId;

      const existing = await activeKeyring(userId);
      if (!existing) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

      if (!kdfParamsAllowed(body.kdf_ops, body.kdf_mem)) return reply.status(400).send({ code: API_ERROR_VAULT_KDF_PARAMS_INVALID });

      // Same binding check as bootstrap: the new auth verifier must be signed by
      // this vault's identity, so a token-thief can't swap in one they control.
      const identity = await prisma.identity.findUnique({ where: { id: existing.identityId } });
      if (!identity) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

      if (!(await authBindingValid(body.auth_public_key, body.auth_pub_sig, identity.signaturePublicKey)))
        return reply.status(400).send({ code: API_ERROR_VAULT_AUTH_BINDING_INVALID });

      // Escrows are bound to a specific vault: only THIS vault's granted
      // relationships gate this write (a start-over's dormant vault keeps its own
      // escrows untouched, see architecture: they die only with the vault).
      const nowMs = Date.now();
      const escrowRows = await prisma.emergencyAccess.findMany({ where: { grantorUserId: userId }, include: { credential: true } });
      const granted = escrowRows.filter((row) => row.credential.vaultId === existing.id && emergencyApprovalHolds(row, nowMs));

      const rearms = body.emergency_rearms ?? [];
      const rearmById = new Map(rearms.map((r) => [r.emergency_access_id, r]));

      // Exact cover: one re-arm per granted relationship, nothing extraneous (an
      // extraneous entry would let a caller swap escrows outside the granted set).
      if (rearms.length !== granted.length || granted.some((row) => !rearmById.has(row.id)))
        return reply.status(400).send({ code: API_ERROR_EMERGENCY_REARM_REQUIRED });

      // Resolve each re-armed escrow's pinned contact identity to its registry row,
      // so it can be stored as an FK. Scoped to THIS relationship's contact: the
      // signature-key column is globally unique, so an unscoped lookup would
      // happily resolve another user's identity row and store it as
      // `granteeIdentityId`, after which GET /trusted would report that stranger's
      // key as the pinned contact identity.
      //
      // Deliberately NOT as strict as the standalone
      // /api/emergency-access/:id/rearm route, which additionally demands the
      // contact's CURRENT active identity and key version. This path is the forced
      // rotation right after an emergency unlock: it is the write that kills a
      // phrase a contact has already read, so it must not be refusable because the
      // contact happened to rotate something in the meantime. Staleness here is
      // advisory (the escrow audit flags it, and the row is re-armed anyway).
      const granteeIdentityIdByRow = new Map<string, string>();

      for (const row of granted) {
        const rearm = rearmById.get(row.id)!;

        if (!kdfParamsAllowed(rearm.credential.kdf_ops, rearm.credential.kdf_mem))
          return reply.status(400).send({ code: API_ERROR_VAULT_KDF_PARAMS_INVALID });

        const valid = await verifyEscrowSubmission(
          {
            grantorUserId: userId,
            granteeUserId: row.granteeUserId,
            waitTimeDays: row.waitTimeDays,
            credential: rearm.credential,
            escrow: rearm,
          },
          identity.signaturePublicKey
        );
        if (!valid) return reply.status(400).send({ code: API_ERROR_EMERGENCY_ESCROW_INVALID });

        const granteeIdentityRow = await prisma.identity.findFirst({
          where: { userId: row.granteeUserId, signaturePublicKey: Buffer.from(base64ToUint8(rearm.grantee_identity_public_key)) },
        });
        if (!granteeIdentityRow) return reply.status(400).send({ code: API_ERROR_EMERGENCY_ESCROW_INVALID });

        granteeIdentityIdByRow.set(row.id, granteeIdentityRow.id);
      }

      try {
        await prisma.$transaction(
          async (tx) => {
            const primary = await tx.vaultCredential.findFirstOrThrow({ where: { vaultId: existing.id, type: 'primary' } });

            await tx.vaultCredential.update({
              where: { id: primary.id },
              data: {
                wrappedVrk: body.wrapped_vrk,
                authPublicKey: Buffer.from(base64ToUint8(body.auth_public_key)),
                authPubSig: Buffer.from(base64ToUint8(body.auth_pub_sig)),
                kdfOps: body.kdf_ops,
                kdfMem: body.kdf_mem,
                lang: body.lang,
              },
            });

            for (const row of granted) {
              const rearm = rearmById.get(row.id)!;

              // Fresh dormant credential first, re-point the relationship at it
              // (resetting it to a plain confirmed state), THEN burn the revealed
              // one: the relationship row must never dangle without a credential
              // (deleting its credential cascades the row away).
              const fresh = await tx.vaultCredential.create({
                data: {
                  vaultId: existing.id,
                  type: 'emergency',
                  wrappedVrk: rearm.credential.wrapped_vrk,
                  authPublicKey: Buffer.from(base64ToUint8(rearm.credential.auth_public_key)),
                  authPubSig: Buffer.from(base64ToUint8(rearm.credential.auth_pub_sig)),
                  kdfOps: rearm.credential.kdf_ops,
                  kdfMem: rearm.credential.kdf_mem,
                  lang: rearm.credential.lang,
                },
              });

              await tx.emergencyAccess.update({
                where: { id: row.id },
                data: {
                  credentialId: fresh.id,
                  wrappedPhraseForGrantee: rearm.wrapped_phrase_for_grantee,
                  granteeIdentityId: granteeIdentityIdByRow.get(row.id)!,
                  granteeKeyVersion: rearm.grantee_key_version,
                  escrowSignature: Buffer.from(base64ToUint8(rearm.escrow_signature)),
                  escrowCreatedAt: new Date(rearm.escrow_created_at_millis),
                  status: 'confirmed',
                  recoveryRequestedAt: null,
                  lastNotifiedAt: null,
                },
              });

              await tx.vaultCredential.delete({ where: { id: row.credentialId } });
            }
          },
          { isolationLevel: 'Serializable' }
        );
      } catch (err) {
        if (isRetryableRegistrationError(err)) return reply.status(409).send({ code: API_ERROR_CONCURRENT_REGISTRATION });
        throw err;
      }

      // Both sides learn the recovery completed (best-effort: the write above is
      // already durable, a mail hiccup must not fail it).
      if (granted.length > 0) {
        notifyVaultRecovered(
          userId,
          granted.map((row) => row.granteeUserId)
        ).catch((err) => request.log.error({ err }, 'emergency recovered emails failed'));
      }

      return { updated: true, rearmed: granted.length };
    },
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

  app.withTypeProvider<ZodTypeProvider>().post('/api/vault/approvals/request', {
    ...SKIP_SIG,
    schema: {
      body: z.object({
        device_public_key: z.string().min(1).max(MAX_DEVICE_KEY_B64),
      }),
      response: { 200: z.object({ request_id: z.string(), device_public_key: z.string() }), ...errorResponses(429) },
    },
    handler: async (request, reply) => {
      const body = request.body;
      assertUserId(request);
      const userId = request.userId;

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
    },
  });

  app.withTypeProvider<ZodTypeProvider>().post('/api/vault/approvals/:requestId/approve', {
    schema: {
      params: RequestIdParamsSchema,
      body: z.object({
        wrapped_device_bootstrap: z.string().min(1).max(MAX_WRAPPED_VRK_B64),
      }),
      response: { 200: z.object({ approved: z.boolean() }), ...errorResponses(404) },
    },
    handler: async (request, reply) => {
      assertUserId(request);
      const body = request.body;
      const approval = await loadOwnedApproval(request.params.requestId, request.userId);

      // Only the owner can approve their own pending, unexpired device.
      if (!approval) return reply.status(404).send({ code: API_ERROR_VAULT_APPROVAL_NOT_FOUND });

      await prisma.vaultApproval.update({
        where: { requestId: approval.requestId },
        data: { wrappedDeviceBootstrap: body.wrapped_device_bootstrap },
      });

      return { approved: true };
    },
  });

  app.withTypeProvider<ZodTypeProvider>().get('/api/vault/approvals/:requestId', {
    ...SKIP_SIG,
    schema: {
      params: RequestIdParamsSchema,
      response: { 200: z.object({ wrapped_device_bootstrap: z.string(), device_public_key: z.string() }), ...errorResponses(404, 425) },
    },
    handler: async (request, reply) => {
      assertUserId(request);
      const approval = await loadOwnedApproval(request.params.requestId, request.userId);

      if (!approval) return reply.status(404).send({ code: API_ERROR_VAULT_APPROVAL_NOT_FOUND });

      if (!approval.wrappedDeviceBootstrap) return reply.status(425).send({ code: API_ERROR_VAULT_APPROVAL_NOT_READY });

      // One-shot: consume once collected.
      await prisma.vaultApproval.delete({ where: { requestId: approval.requestId } });

      return { wrapped_device_bootstrap: approval.wrappedDeviceBootstrap, device_public_key: approval.devicePublicKey };
    },
  });

  // Enrolled device, no-camera fallback: list this user's pending (not-yet-approved,
  // unexpired) requests so the manual decimal-fingerprint path can find the right
  // key without the user having to type the requestId. Owner-scoped. Static route,
  // so it takes precedence over `/approvals/:requestId`.
  app.withTypeProvider<ZodTypeProvider>().get('/api/vault/approvals/pending', {
    schema: {
      response: {
        200: z.object({
          approvals: z.array(z.object({ request_id: z.string(), device_public_key: z.string() })),
        }),
      },
    },
    handler: async (request) => {
      assertUserId(request);
      const pending = await prisma.vaultApproval.findMany({
        where: { userId: request.userId, wrappedDeviceBootstrap: null, expiresAt: { gt: new Date() } },
        select: { requestId: true, devicePublicKey: true },
      });

      return { approvals: pending.map((a) => ({ request_id: a.requestId, device_public_key: a.devicePublicKey })) };
    },
  });
}
