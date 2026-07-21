import type { FastifyInstance } from 'fastify';
import { randomUUID } from 'node:crypto';

import { uint8ToBase64 } from '@encryption/src/crypto';
import { base64ToUint8, importPublicKeyFromBase64 } from '@encryption/src/crypto/encryption-backup';
import { createKeyPossessionChallenge } from '@encryption/src/crypto/key-possession-challenge';
import { verifyKeyRegistration } from '@encryption/src/crypto/key-registration';
import { assertValidSignaturePublicKey } from '@encryption/src/crypto/signature';
import { prisma } from '@encryption/src/prisma/client';
import { env } from '@encryption/src/server/env';
import {
  type CompleteTxResult,
  completeRegistrationInTx,
  completeResultToHttpError,
  isRetryableRegistrationError,
  loadAndVerifyPossession,
} from '@encryption/src/server/routes/registration-core';
import { MAX_CONTINUITY_HOPS } from '@encryption/src/shared/constants';
import {
  API_ERROR_CONCURRENT_REGISTRATION,
  API_ERROR_FORBIDDEN_OTHER_USER,
  API_ERROR_INVALID_KEY_BINDING,
  API_ERROR_INVALID_PUBLIC_KEY,
  API_ERROR_INVALID_TIMESTAMP,
  API_ERROR_NO_ACTIVE_KEY,
  API_ERROR_RATE_LIMIT_CHALLENGES,
} from '@encryption/src/shared/error-codes';
import { CompleteKeyPossessionBodySchema, InitKeyPossessionBodySchema } from '@encryption/src/shared/schemas/key-possession';
import { type ContinuityLinkWire, GetPublicKeysQuerySchema } from '@encryption/src/shared/schemas/public-key';

const CHALLENGE_TTL_SECONDS = 120;
// Bound how many LIVE (unexpired) possession challenges a user may hold at once.
// Each init writes a challenge row before any PoP is proven, so without a cap a
// caller could flood the table with init requests. Counting only live rows means
// the opportunistic cleanup of expired rows can never undercount this bound.
const MAX_OUTSTANDING_CHALLENGES = 10;
// How far the client-asserted creation timestamp may drift from the server
// clock. Generous enough for slow networks / mild clock skew, tight enough
// that a row can't be meaningfully backdated. The timestamp is inside the
// signed payload, so this only bounds honest clock error — it is not a
// security boundary on its own.
const TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000;

export async function publicKeysRoute(app: FastifyInstance): Promise<void> {
  // ----- Listing & disabling --------------------------------------------------

  // Public directory data, so UNAUTHENTICATED on purpose, like the /:userId and
  // /continuity lookups below: the registry only ever exposes public keys (never
  // anything private), and it must be reachable without a token because the vault
  // iframe fetches it during a product-initiated share, which carries no OIDC
  // token (sharing is a product operation, not a privileged one). The list is
  // capped (<= 100 ids) by the schema to bound the query and blunt bulk scraping;
  // a public directory is inherently enumerable and that is the accepted design.
  app.get('/api/public-keys', {
    handler: async (request) => {
      // Already split, trimmed, bounded (<= 100 ids), and EXCLUSIVE (exactly
      // one form) by the schema. `user_ids` are internal ids; `subs` are OIDC
      // subs resolved through oidc_accounts, active issuer only.
      const query = GetPublicKeysQuerySchema.parse(request.query);

      // internal id -> every queried sub that resolved to it. A user can hold
      // several subs under the SAME issuer (email-fallback linking after an
      // IdP recreated their account), and each queried sub deserves its own
      // echoed entry — collapsing them would make one of the subs read as
      // "no keys" to the caller.
      const subsByUser = new Map<string, string[]>();
      let userIds: string[];

      if (query.subs !== undefined) {
        // Resolution is restricted to the CURRENTLY configured issuer: exactly
        // one exists at a time (cutover, not coexistence), so callers never
        // pass one. Retired-issuer rows are kept (audit trail, operator merge
        // tooling) but deliberately NEVER resolved here: matching them would
        // be fail-open, since a fresh sub colliding with a retired one could
        // return another human's keys, the one wrong answer a key directory
        // must never give. The cost is fail-closed and self-healing: after a
        // provider cutover a user stops resolving (shows as "no keys") until
        // their first post-cutover login re-links their new credential.
        const accounts = await prisma.oidcAccount.findMany({
          where: { issuer: env.OIDC_ISSUER, subject: { in: query.subs } },
        });

        for (const account of accounts) {
          subsByUser.set(account.userId, [...(subsByUser.get(account.userId) ?? []), account.subject]);
        }

        userIds = [...subsByUser.keys()];
      } else {
        userIds = query.user_ids!;
      }

      if (userIds.length === 0) {
        return { keys: [] };
      }

      // The active encryption key joined to the identity that vouches for it, and
      // ONLY when that identity is itself active: disabling an identity hides the
      // user from the directory even though the encryption key row stays valid.
      // Exactly one active EncryptionKey exists per user (rotation disables the
      // previous rows in a transaction), so this yields at most one row per user.
      const keys = await prisma.encryptionKey.findMany({
        where: {
          userId: { in: userIds },
          disabledAt: null,
          identity: { is: { disabledAt: null } },
        },
        include: { identity: true },
      });

      return {
        // One entry per (record, matched sub) pair for `subs` queries so each
        // queried sub finds its echo; plain per-record entries for `user_ids`.
        keys: keys.flatMap((key) => {
          const base = {
            user_id: key.userId,
            encryption_public_key: uint8ToBase64(key.encryptionPublicKey),
            signature_public_key: uint8ToBase64(key.identity.signaturePublicKey),
            key_binding_signature: uint8ToBase64(key.keyBindingSignature),
            version: key.version,
            created_at_millis: key.createdAt.getTime(),
          };
          const matched = subsByUser.get(key.userId);

          return matched ? matched.map((sub) => ({ ...base, sub })) : [base];
        }),
      };
    },
  });

  // Single-user lookup with cache headers. Because `version` is monotonic and
  // a key's record is immutable once registered, a product backend can cache
  // a (user_id, version) record indefinitely and revalidate cheaply with the
  // ETag — the recommended way to verify content signatures without storing
  // public keys itself. A 304 means "same active version, your cache is good".
  app.get<{ Params: { userId: string } }>('/api/public-keys/:userId', async (request, reply) => {
    const { userId } = request.params;

    const key = await prisma.encryptionKey.findFirst({
      where: { userId, disabledAt: null, identity: { is: { disabledAt: null } } },
      orderBy: { version: 'desc' },
      include: { identity: true },
    });

    if (!key) {
      return reply.status(404).send({ code: API_ERROR_NO_ACTIVE_KEY });
    }

    // ETag is the active version: it changes exactly when the user rotates.
    const etag = `"v${key.version}"`;

    if (request.headers['if-none-match'] === etag) {
      return reply.status(304).send();
    }

    // Records are immutable per version, but a user can rotate at any time, so
    // allow short-lived caching plus revalidation rather than long immutability.
    reply.header('Cache-Control', 'private, max-age=60, must-revalidate');
    reply.header('ETag', etag);

    return {
      user_id: key.userId,
      encryption_public_key: uint8ToBase64(key.encryptionPublicKey),
      signature_public_key: uint8ToBase64(key.identity.signaturePublicKey),
      key_binding_signature: uint8ToBase64(key.keyBindingSignature),
      version: key.version,
      created_at_millis: key.createdAt.getTime(),
    };
  });

  // The identity-continuity chain for a user, walked server-side from the
  // CURRENT identity back toward older ones (one link per rotation), bounded by
  // the shared hop cap. A device that pinned an older identity out-of-band uses
  // this to decide whether a NEW fingerprint it just saw legitimately descends
  // from the pinned one, without a fresh out-of-band check. It is public
  // directory data (public keys plus cross-signatures), so no auth is needed;
  // the consumer verifies every link's signature, so the server cannot fabricate
  // trust here — a compromised registry can only withhold links (fail-safe).
  app.get<{ Params: { userId: string } }>('/api/public-keys/:userId/continuity', async (request) => {
    const { userId } = request.params;

    // Start from the identity that vouches for the active encryption key: that is
    // exactly the identity a product presents a fingerprint for, so the head of
    // the chain matches the fingerprint that just mismatched on a device.
    const activeKey = await prisma.encryptionKey.findFirst({
      where: { userId, disabledAt: null, identity: { is: { disabledAt: null } } },
      orderBy: { version: 'desc' },
      include: { identity: true },
    });

    const chain: ContinuityLinkWire[] = [];
    let node = activeKey?.identity ?? null;

    // Follow previousIdentity links; only identities carrying a continuity
    // signature (a genuine rotation cross-signed by the previous key) yield a
    // link. Bounded so a long history cannot make this walk run unbounded.
    for (let hops = 0; node && node.previousIdentityId && node.continuitySignature && hops < MAX_CONTINUITY_HOPS; hops++) {
      const previous = await prisma.identity.findUnique({ where: { id: node.previousIdentityId } });
      if (!previous) break;

      chain.push({
        signature_public_key: uint8ToBase64(node.signaturePublicKey),
        previous_signature_public_key: uint8ToBase64(previous.signaturePublicKey),
        generation: node.generation,
        algo: node.algo,
        continuity_signature: uint8ToBase64(node.continuitySignature),
      });

      node = previous;
    }

    return { chain };
  });

  // Disable the active public key without creating a new one.
  // This is the "start from zero" action — the user loses the ability
  // to decrypt old documents unless they have a backup to restore.
  //
  // Intentionally NOT signature-gated: this is the recovery path used
  // precisely when the user has LOST their keys (and therefore cannot sign),
  // so requiring a signature here would lock out the people who need it most.
  // The JWT already proves it is the account owner acting.
  app.delete('/api/public-keys', {
    preHandler: async (request) => {
      await app.verifyJWT(request);
    },
    handler: async (request, reply) => {
      const userId = request.userId!;

      // Disabling turns off the IDENTITY, not the encryption key. The identity is
      // what makes the user discoverable (directory + TOFU); hiding it removes the
      // user from the registry, so others can no longer pull the encryption key to
      // share with them. The encryption key row stays ACTIVE and valid on purpose:
      // reactivating the identity (via the VRK/phrase-authenticated
      // /api/vault/reactivate) brings the SAME last key back live, without a
      // rotation. The vault keyring is disabled too (identity and vault are
      // coupled), so it stops being the sync target until reactivation. Nothing is
      // deleted, so a backup can always recover the vault.
      const now = new Date();
      const [updated] = await prisma.$transaction([
        prisma.identity.updateMany({ where: { userId, disabledAt: null }, data: { disabledAt: now } }),
        prisma.vaultKeyring.updateMany({ where: { userId, disabledAt: null }, data: { disabledAt: now } }),
      ]);

      if (updated.count === 0) {
        return reply.status(404).send({ code: API_ERROR_NO_ACTIVE_KEY });
      }

      return { disabled: true };
    },
  });

  // The next monotonic numbers this user must register, counting DISABLED rows
  // too (versions and generations are never reused). A client reads this before
  // signing a fresh key, notably when re-onboarding after a reset where no active
  // key remains, so it signs `max + 1` and the registration does not conflict.
  app.get('/api/public-keys/next', {
    preHandler: async (request) => {
      await app.verifyJWT(request);
    },
    handler: async (request) => {
      const userId = request.userId!;

      const [keyAggregate, identityAggregate] = await Promise.all([
        prisma.encryptionKey.aggregate({ where: { userId }, _max: { version: true } }),
        prisma.identity.aggregate({ where: { userId }, _max: { generation: true } }),
      ]);

      return {
        next_version: (keyAggregate._max.version ?? 0) + 1,
        next_generation: (identityAggregate._max.generation ?? 0) + 1,
      };
    },
  });

  // ----- Two-phase registration with proof of possession of BOTH keys --------
  //
  // The caller must prove they hold BOTH private keys before a record is
  // committed, and the record's identity binding must be internally coherent:
  //
  //   init     : verify the binding signature (proves the signature key signed
  //              this exact encryption-key + metadata) and the timestamp skew,
  //              then issue an X-Wing PoP challenge for the encryption key.
  //   complete : verify the HMAC (encryption-key PoP) AND an Ed25519 signature
  //              over the challenge id (signature-key PoP), enforce monotonic
  //              versioning, then promote the candidate into an active key.
  //
  // The complete-side write logic lives in registration-core.ts so the vault
  // bootstrap can run the identical registration inside its own transaction.

  app.post('/api/public-keys/register/init', {
    preHandler: async (request) => {
      await app.verifyJWT(request);
    },
    handler: async (request, reply) => {
      const body = InitKeyPossessionBodySchema.parse(request.body);
      const userId = request.userId!;

      // user_id in the body must match the authenticated INTERNAL user id —
      // safety check against a caller passing the wrong identifier (an OIDC
      // sub or a product-scoped id would fail here).
      if (body.user_id !== userId) {
        return reply.status(403).send({ code: API_ERROR_FORBIDDEN_OTHER_USER });
      }

      // Opportunistic cleanup of this user's expired challenges, so abandoned
      // inits don't accumulate without a cron. Mirrors the approvals pattern.
      const now = new Date();
      await prisma.keyPossessionChallenge.deleteMany({ where: { userId, expiresAt: { lt: now } } });

      // Cap the number of LIVE challenges a user can hold, so a caller cannot
      // flood the table with init requests before completing any. Counting only
      // unexpired rows keeps the cleanup above from undercounting the bound.
      const outstanding = await prisma.keyPossessionChallenge.count({ where: { userId, expiresAt: { gt: now } } });

      if (outstanding >= MAX_OUTSTANDING_CHALLENGES) {
        return reply.status(429).send({ code: API_ERROR_RATE_LIMIT_CHALLENGES });
      }

      // Parse both candidate public keys — surfaces malformed input early and
      // lets libsodium reject anything that isn't a valid key before any work.
      let encryptionPublicKeyBytes: Uint8Array;

      try {
        encryptionPublicKeyBytes = importPublicKeyFromBase64(body.encryption_public_key);
        const signatureRawKey = importPublicKeyFromBase64(body.signature_public_key);
        await assertValidSignaturePublicKey(signatureRawKey);
      } catch {
        return reply.status(400).send({ code: API_ERROR_INVALID_PUBLIC_KEY });
      }

      // The client asserts (and signs) its own creation time. Bound the drift
      // so a row can't be meaningfully backdated; the signature still covers
      // the exact value, this only catches honest clock error / abuse.
      if (Math.abs(Date.now() - body.created_at_millis) > TIMESTAMP_TOLERANCE_MS) {
        return reply.status(400).send({ code: API_ERROR_INVALID_TIMESTAMP });
      }

      // Verify the identity binding NOW, so a record whose signature doesn't
      // cover its own keys/metadata never even gets a challenge issued.
      const bindingValid = await verifyKeyRegistration({
        userId,
        version: body.version,
        createdAtMillis: body.created_at_millis,
        encryptionPublicKeyB64: body.encryption_public_key,
        signaturePublicKeyB64: body.signature_public_key,
        keyBindingSignatureB64: body.key_binding_signature,
      });

      if (!bindingValid) {
        return reply.status(400).send({ code: API_ERROR_INVALID_KEY_BINDING });
      }

      // Generate the challenge id up front and bind the HMAC to it before the
      // row is written. The PoP challenge targets the ENCRYPTION key.
      const challengeId = randomUUID();
      const { ciphertext, expectedHmac } = await createKeyPossessionChallenge(encryptionPublicKeyBytes, challengeId);
      const expiresAt = new Date(Date.now() + CHALLENGE_TTL_SECONDS * 1000);

      await prisma.keyPossessionChallenge.create({
        data: {
          id: challengeId,
          userId,
          encryptionPublicKey: Buffer.from(base64ToUint8(body.encryption_public_key)),
          signaturePublicKey: Buffer.from(base64ToUint8(body.signature_public_key)),
          keyBindingSignature: Buffer.from(base64ToUint8(body.key_binding_signature)),
          version: body.version,
          signedCreatedAt: new Date(body.created_at_millis),
          // libsodium hands back a Uint8Array with an unconstrained buffer
          // generic; Prisma's Bytes input wants an ArrayBuffer-backed view, so
          // we copy through Buffer.from to land in the right shape.
          expectedHmac: Buffer.from(expectedHmac),
          expiresAt,
        },
      });

      return {
        challenge_id: challengeId,
        ciphertext: uint8ToBase64(ciphertext),
      };
    },
  });

  app.post('/api/public-keys/register/complete', {
    preHandler: async (request) => {
      await app.verifyJWT(request);
    },
    handler: async (request, reply) => {
      const body = CompleteKeyPossessionBodySchema.parse(request.body);
      const userId = request.userId!;

      // Read-only proof checks first, outside the write transaction.
      const check = await loadAndVerifyPossession(userId, body);

      if (!check.ok) {
        return reply.status(check.status).send({ code: check.code });
      }

      // All writes go through a Serializable transaction so concurrent
      // completes for the same user can't both create a fresh active key.
      let result: CompleteTxResult;

      try {
        // completeRegistrationInTx never mints an identity, so this standalone
        // path can only ever rotate or re-enable an EXISTING, vault-backed
        // identity; a never-bootstrapped identity returns `no_vault`. Only the
        // atomic bootstrap (POST /api/vault) mints, coupling identity + vault.
        result = await prisma.$transaction((tx) => completeRegistrationInTx(tx, userId, check.challenge), {
          isolationLevel: 'Serializable',
        });
      } catch (err) {
        if (isRetryableRegistrationError(err)) {
          // Concurrent completes for the same user; PG aborted ours or the
          // unique (userId,version) constraint tripped. Safe to retry — the
          // challenge is single-use, so at most one racer ultimately wins.
          return reply.status(409).send({ code: API_ERROR_CONCURRENT_REGISTRATION });
        }
        throw err;
      }

      if (result.kind !== 'success') {
        const mapped = completeResultToHttpError(result)!;

        return reply.status(mapped.status).send(mapped.params ? { code: mapped.code, params: mapped.params } : { code: mapped.code });
      }

      return {
        user_id: result.userId,
        encryption_public_key: result.encryptionPublicKey,
        signature_public_key: result.signaturePublicKey,
        key_binding_signature: result.keyBindingSignature,
        version: result.version,
        created_at_millis: result.createdAtMillis,
      };
    },
  });
}
