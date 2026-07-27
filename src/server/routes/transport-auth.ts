import type { FastifyInstance, FastifyRequest } from 'fastify';
import assert from 'node:assert';

import { uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { verifyIdentityContinuity } from '@encryption/src/crypto/key-registration';
import { REQUEST_SIG_HEADER, readProofSubject, verifyRequestProof } from '@encryption/src/crypto/request-proof';
import { prisma } from '@encryption/src/prisma/client';
import { MAX_CONTINUITY_HOPS } from '@encryption/src/shared/constants';
import { API_ERROR_VAULT_REQUEST_SIGNATURE_INVALID } from '@encryption/src/shared/error-codes';

// Per-route auth tier (see architecture.md §7.1). Default (no flag) = JWT +
// identity signature (tier 2, interactive + sensitive).
// - SKIP_SIG: JWT only, no signature — cold prerequisites / PoP flows / the
//   lost-password disable, i.e. where the caller structurally cannot sign.
// - SIG_ONLY: identity signature only, NO JWT — the silent data-plane that must
//   run in the background (the vault holds the key, the interface/JWT may be
//   absent). `userId` comes from the signed `sub`.
export const SKIP_SIG = { config: { skipRequestSignature: true } };
export const SIG_ONLY = { config: { signatureOnly: true } };

// The transport-auth preValidation hook sets `request.userId` and rejects with
// 401 before the handler runs otherwise, so a missing userId inside a handler is
// not a user condition: it means the route was registered outside this hook (a
// wiring bug). Assert the invariant rather than dressing it as an auth error;
// this narrows the type (dropping the `!`) and, if ever violated, fails loud as a
// 500 instead of feeding `undefined` to Prisma (where a dropped filter would
// return every user's rows).
export function assertUserId(request: FastifyRequest): asserts request is FastifyRequest & { userId: string } {
  assert(request.userId, 'request.userId is missing: this route is not behind transport auth');
}

// Grace window during which a SUPERSEDED (but not revoked) identity key may still
// authenticate a lagging device after a migration. Set to the same ~1 year as the
// superseded-vault content retention (§9), so the two windows reinforce each other.
const IDENTITY_AUTH_GRACE_MS = 365 * 24 * 60 * 60 * 1000;

// The user's ACTIVE identity WIRE public key (fast path: the overwhelmingly
// common signer). Null if the user has no identity at all.
export async function activeIdentityWireKey(userId: string): Promise<Uint8Array | null> {
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

/**
 * Install, on one route plugin, the tiered secure-by-default transport auth
 * used by the vault and emergency-access APIs (§7.1):
 *  - SIG_ONLY -> identity signature ONLY, no JWT; userId comes from the signed
 *    sub (verified against that user's key, so a forged sub cannot pass).
 *  - SKIP_SIG -> JWT only.
 *  - default  -> JWT + identity signature, the signature's sub bound to the JWT.
 * A new route falls under the strictest default (JWT+sig) unless it opts out, so
 * forgetting fails loud (rejects a legitimate call), never silently open.
 *
 * Also keeps the RAW JSON body (still parsing it as usual) so the signature
 * middleware can verify the body digest against the exact bytes the client
 * signed, not a re-serialization. Scoped to the registering plugin only.
 */
export function registerTransportAuth(app: FastifyInstance): void {
  app.addContentTypeParser('application/json', { parseAs: 'string' }, (request, body, done) => {
    (request as { rawBody?: string }).rawBody = body as string;

    if (body === '') return done(null, undefined);

    try {
      done(null, JSON.parse(body as string));
    } catch (err) {
      done(err as Error);
    }
  });

  // `preValidation`, NOT `preHandler`: the body is parsed by then (the hook needs
  // it for the body digest) but schema validation has not run yet, so an
  // unauthenticated caller is rejected 401 BEFORE its payload reaches the
  // validator. On `preHandler` the order inverts and a forged-signature request
  // with a malformed body answers 400, leaking that the signature was never the
  // reason it failed.
  app.addHook('preValidation', async (request, reply) => {
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
    assertUserId(request); // verifyJWT set it or already rejected.

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
    if (!(await verifyIdentityRequest(request, request.userId, token, nowMs))) return reject();
  });
}
