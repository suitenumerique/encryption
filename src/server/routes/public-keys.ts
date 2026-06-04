import { randomUUID } from 'node:crypto';

import type { FastifyInstance } from 'fastify';

import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client';

import { uint8ToBase64 } from '@encryption/src/crypto';
import { base64ToUint8, importPublicKeyFromBase64 } from '@encryption/src/crypto/encryption-backup';
import { encodePopChallengeMessage, verifyKeyRegistration } from '@encryption/src/crypto/key-registration';
import { createKeyPossessionChallenge, verifyChallengeResponse } from '@encryption/src/crypto/key-possession-challenge';
import { assertValidSignaturePublicKey, verifyDetached } from '@encryption/src/crypto/signature';
import { prisma } from '@encryption/src/prisma/client';
import {
  API_ERROR_CHALLENGE_EXPIRED,
  API_ERROR_CHALLENGE_INVALID_RESPONSE,
  API_ERROR_CHALLENGE_NOT_FOUND,
  API_ERROR_CONCURRENT_REGISTRATION,
  API_ERROR_FORBIDDEN_OTHER_USER,
  API_ERROR_INVALID_CHALLENGE_SIGNATURE,
  API_ERROR_INVALID_KEY_BINDING,
  API_ERROR_INVALID_PUBLIC_KEY,
  API_ERROR_INVALID_TIMESTAMP,
  API_ERROR_KEY_VERSION_CONFLICT,
  API_ERROR_NO_ACTIVE_KEY,
  API_ERROR_RATE_LIMIT_KEYS,
} from '@encryption/src/shared/error-codes';
import { CompleteKeyPossessionBodySchema, InitKeyPossessionBodySchema } from '@encryption/src/shared/schemas/key-possession';
import { GetPublicKeysQuerySchema } from '@encryption/src/shared/schemas/public-key';

const RATE_LIMIT_WINDOW_DAYS = 30;
const RATE_LIMIT_MAX_CREATIONS = 10;
const CHALLENGE_TTL_SECONDS = 120;
// How far the client-asserted creation timestamp may drift from the server
// clock. Generous enough for slow networks / mild clock skew, tight enough
// that a row can't be meaningfully backdated. The timestamp is inside the
// signed payload, so this only bounds honest clock error — it is not a
// security boundary on its own.
const TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000;

// PostgreSQL serialization-failure (40001) surfaces as P2034 in Prisma, and a
// unique-constraint violation as P2002. Either can happen when two completes
// for the same user race for the same next version; both are safe to retry.
const PRISMA_SERIALIZATION_FAILURE = 'P2034';
const PRISMA_UNIQUE_VIOLATION = 'P2002';

function isRetryableRegistrationError(err: unknown): boolean {
  return (
    err instanceof PrismaClientKnownRequestError &&
    (err.code === PRISMA_SERIALIZATION_FAILURE || err.code === PRISMA_UNIQUE_VIOLATION)
  );
}

// Discriminated result type from the complete-PoP transaction. Returning a
// value (rather than throwing) lets every business-logic exit commit a
// no-op transaction cleanly while still mapping to a stable HTTP code.
type CompleteTxResult =
  | {
      kind: 'success';
      userId: string;
      encryptionPublicKey: string;
      signaturePublicKey: string;
      keyBindingSignature: string;
      version: number;
      createdAtMillis: number;
    }
  | { kind: 'consumed' }
  | { kind: 'version_conflict' }
  | { kind: 'rate_limit' };

export async function publicKeysRoute(app: FastifyInstance): Promise<void> {
  // ----- Listing & disabling --------------------------------------------------

  app.get('/api/public-keys', async (request) => {
    const query = GetPublicKeysQuerySchema.parse(request.query);
    const userIds = query.user_ids.split(',').map((id) => id.trim());

    const keys = await prisma.publicKey.findMany({
      where: {
        userId: { in: userIds },
        disabledAt: null,
      },
    });

    return {
      keys: keys.map((key) => ({
        user_id: key.userId,
        encryption_public_key: key.encryptionPublicKey,
        signature_public_key: key.signaturePublicKey,
        key_binding_signature: key.keyBindingSignature,
        version: key.version,
        created_at_millis: key.createdAt.getTime(),
      })),
    };
  });

  // Single-user lookup with cache headers. Because `version` is monotonic and
  // a key's record is immutable once registered, a product backend can cache
  // a (user_id, version) record indefinitely and revalidate cheaply with the
  // ETag — the recommended way to verify content signatures without storing
  // public keys itself. A 304 means "same active version, your cache is good".
  app.get<{ Params: { userId: string } }>('/api/public-keys/:userId', async (request, reply) => {
    const { userId } = request.params;

    const key = await prisma.publicKey.findFirst({
      where: { userId, disabledAt: null },
      orderBy: { version: 'desc' },
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
      encryption_public_key: key.encryptionPublicKey,
      signature_public_key: key.signaturePublicKey,
      key_binding_signature: key.keyBindingSignature,
      version: key.version,
      created_at_millis: key.createdAt.getTime(),
    };
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

      const updated = await prisma.publicKey.updateMany({
        where: { userId, disabledAt: null },
        data: { disabledAt: new Date() },
      });

      if (updated.count === 0) {
        return reply.status(404).send({ code: API_ERROR_NO_ACTIVE_KEY });
      }

      return { disabled: true };
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
  // See src/crypto/key-possession-challenge.ts and src/crypto/key-registration.ts.

  app.post('/api/public-keys/register/init', {
    preHandler: async (request) => {
      await app.verifyJWT(request);
    },
    handler: async (request, reply) => {
      const body = InitKeyPossessionBodySchema.parse(request.body);
      const userId = request.userId!;

      // user_id in the body must match the JWT sub — safety check against
      // a caller passing the wrong identifier (e.g. a product-scoped id).
      if (body.user_id !== userId) {
        return reply.status(403).send({ code: API_ERROR_FORBIDDEN_OTHER_USER });
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
          encryptionPublicKey: body.encryption_public_key,
          signaturePublicKey: body.signature_public_key,
          keyBindingSignature: body.key_binding_signature,
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

      // Read-only checks first, outside the write transaction. Any state
      // observed here is re-checked inside the tx to avoid TOCTOU.
      const challenge = await prisma.keyPossessionChallenge.findUnique({
        where: { id: body.challenge_id },
      });

      // Treat "not mine" the same as "not found" — never confirm to a
      // caller that someone else has a challenge with this id.
      if (!challenge || challenge.userId !== userId) {
        return reply.status(404).send({ code: API_ERROR_CHALLENGE_NOT_FOUND });
      }

      if (challenge.expiresAt.getTime() < Date.now()) {
        // Best-effort cleanup; ignore concurrent deletes.
        await prisma.keyPossessionChallenge.deleteMany({ where: { id: challenge.id } });

        return reply.status(410).send({ code: API_ERROR_CHALLENGE_EXPIRED });
      }

      // Encryption-key PoP: HMAC the client derived from decapsulating our
      // X-Wing ciphertext must match the tag we stored at init.
      const received = base64ToUint8(body.response);
      const hmacOk = await verifyChallengeResponse(new Uint8Array(challenge.expectedHmac), received);

      if (!hmacOk) {
        // Don't delete on first miss — the HMAC could be a transport glitch.
        // Keep the row until expiry; the caller can retry with the same id.
        return reply.status(400).send({ code: API_ERROR_CHALLENGE_INVALID_RESPONSE });
      }

      // Signature-key PoP: an Ed25519 signature over the challenge id, made by
      // the candidate identity key. Proves the caller also holds the signature
      // private key (not just the encryption one).
      let signaturePopOk = false;

      try {
        const signatureRawKey = importPublicKeyFromBase64(challenge.signaturePublicKey);
        const challengeMessage = encodePopChallengeMessage(challenge.id);
        signaturePopOk = await verifyDetached(base64ToUint8(body.challenge_signature), challengeMessage, signatureRawKey);
      } catch {
        signaturePopOk = false;
      }

      if (!signaturePopOk) {
        return reply.status(400).send({ code: API_ERROR_INVALID_CHALLENGE_SIGNATURE });
      }

      // All writes go through a Serializable transaction so concurrent
      // completes for the same user can't both create a fresh active key
      // (PG aborts one with 40001/P2034, or the (userId,version) unique
      // constraint trips with P2002). Re-reading + deleting the challenge row
      // inside the tx also makes it a single-use mutex against double-spend.
      let result: CompleteTxResult;

      try {
        result = await prisma.$transaction(
          async (tx): Promise<CompleteTxResult> => {
            const fresh = await tx.keyPossessionChallenge.findUnique({
              where: { id: challenge.id },
            });

            if (!fresh) {
              return { kind: 'consumed' };
            }

            // Rate-limit at completion only: an attacker who can't pass PoP
            // can't burn the user's quota, while honest churners are bounded.
            const windowStart = new Date();
            windowStart.setDate(windowStart.getDate() - RATE_LIMIT_WINDOW_DAYS);
            const recentCreations = await tx.publicKey.count({
              where: { userId, createdAt: { gte: windowStart } },
            });

            if (recentCreations >= RATE_LIMIT_MAX_CREATIONS) {
              return { kind: 'rate_limit' };
            }

            // Monotonic versioning: the candidate version must be exactly
            // (current max for this user) + 1. The signature covers `version`,
            // so the server can't silently renumber — a mismatch means the
            // client signed against a stale view and must refetch + re-sign.
            const aggregate = await tx.publicKey.aggregate({
              where: { userId },
              _max: { version: true },
            });
            const expectedVersion = (aggregate._max.version ?? 0) + 1;

            if (fresh.version !== expectedVersion) {
              return { kind: 'version_conflict' };
            }

            await tx.publicKey.updateMany({
              where: { userId, disabledAt: null },
              data: { disabledAt: new Date() },
            });

            const created = await tx.publicKey.create({
              data: {
                userId,
                encryptionPublicKey: fresh.encryptionPublicKey,
                signaturePublicKey: fresh.signaturePublicKey,
                keyBindingSignature: fresh.keyBindingSignature,
                version: fresh.version,
                // The signed timestamp becomes the row's createdAt, so later
                // verifications (which sign over created_at) keep matching.
                createdAt: fresh.signedCreatedAt,
              },
            });

            // PoP succeeded → the challenge has done its job and must not be
            // replayed. Deleting inside the tx makes this row a mutex against
            // any double-spend of the same id.
            await tx.keyPossessionChallenge.delete({ where: { id: challenge.id } });

            return {
              kind: 'success',
              userId: created.userId,
              encryptionPublicKey: created.encryptionPublicKey,
              signaturePublicKey: created.signaturePublicKey,
              keyBindingSignature: created.keyBindingSignature,
              version: created.version,
              createdAtMillis: created.createdAt.getTime(),
            };
          },
          // Prisma's TransactionIsolationLevel type is a string-literal union,
          // so passing 'Serializable' directly is fully type-safe.
          { isolationLevel: 'Serializable' }
        );
      } catch (err) {
        if (isRetryableRegistrationError(err)) {
          // Concurrent completes for the same user; PG aborted ours or the
          // unique (userId,version) constraint tripped. Safe to retry — the
          // challenge is single-use, so at most one racer ultimately wins.
          return reply.status(409).send({ code: API_ERROR_CONCURRENT_REGISTRATION });
        }
        throw err;
      }

      switch (result.kind) {
        case 'consumed':
          return reply.status(404).send({ code: API_ERROR_CHALLENGE_NOT_FOUND });
        case 'version_conflict':
          // The client raced another device or signed against a stale view.
          // It should refetch its active version, re-sign, and retry init.
          return reply.status(409).send({ code: API_ERROR_KEY_VERSION_CONFLICT });
        case 'rate_limit':
          return reply.status(429).send({
            code: API_ERROR_RATE_LIMIT_KEYS,
            params: { max: RATE_LIMIT_MAX_CREATIONS, days: RATE_LIMIT_WINDOW_DAYS },
          });
        case 'success':
          return {
            user_id: result.userId,
            encryption_public_key: result.encryptionPublicKey,
            signature_public_key: result.signaturePublicKey,
            key_binding_signature: result.keyBindingSignature,
            version: result.version,
            created_at_millis: result.createdAtMillis,
          };
      }
    },
  });
}
