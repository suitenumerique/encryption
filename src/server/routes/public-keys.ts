import { randomUUID } from 'node:crypto';

import type { FastifyInstance } from 'fastify';

import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client';

import { uint8ToBase64 } from '@encryption/src/crypto';
import { base64ToUint8, importPublicKeyFromBase64 } from '@encryption/src/crypto/encryption-backup';
import { createKeyPossessionChallenge, verifyChallengeResponse } from '@encryption/src/crypto/key-possession-challenge';
import { prisma } from '@encryption/src/prisma/client';
import {
  API_ERROR_CHALLENGE_EXPIRED,
  API_ERROR_CHALLENGE_INVALID_RESPONSE,
  API_ERROR_CHALLENGE_NOT_FOUND,
  API_ERROR_CONCURRENT_REGISTRATION,
  API_ERROR_FORBIDDEN_OTHER_USER,
  API_ERROR_NO_ACTIVE_KEY,
  API_ERROR_RATE_LIMIT_KEYS,
} from '@encryption/src/shared/error-codes';
import { CompleteKeyPossessionBodySchema, InitKeyPossessionBodySchema } from '@encryption/src/shared/schemas/key-possession';
import { GetPublicKeysQuerySchema } from '@encryption/src/shared/schemas/public-key';

const RATE_LIMIT_WINDOW_DAYS = 30;
const RATE_LIMIT_MAX_CREATIONS = 10;
const CHALLENGE_TTL_SECONDS = 120;

// PostgreSQL serialization-failure (40001) surfaces as P2034 in Prisma.
// Catching it lets the route return a stable code so the client can retry.
// `PrismaClientKnownRequestError` is re-exported from the CJS runtime
// (`@prisma/client/runtime/client`) — importing the generated `Prisma`
// namespace here would pull in `import.meta` and break Jest's CJS env.
const PRISMA_SERIALIZATION_FAILURE = 'P2034';

function isSerializationFailure(err: unknown): boolean {
  return err instanceof PrismaClientKnownRequestError && err.code === PRISMA_SERIALIZATION_FAILURE;
}

// Discriminated result type from the complete-PoP transaction. Returning a
// value (rather than throwing) lets every business-logic exit commit a
// no-op transaction cleanly while still mapping to a stable HTTP code.
type CompleteTxResult =
  | { kind: 'success'; userId: string; publicKey: string }
  | { kind: 'consumed' }
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
        public_key: key.publicKey,
      })),
    };
  });

  // Disable the active public key without creating a new one.
  // This is the "start from zero" action — the user loses the ability
  // to decrypt old documents unless they have a backup to restore.
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

  // ----- Two-phase registration with proof of possession ---------------------
  //
  // Without PoP, a caller with a valid ProConnect JWT could register a
  // public key whose private counterpart they don't actually hold —
  // either by accident (frontend bug) or to claim a published pubkey as
  // their own. The flow forces the caller to decapsulate a
  // server-generated X-Wing ciphertext before the key is committed.
  //
  // See src/crypto/key-possession-challenge.ts for the full protocol.

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

      // Parse the candidate public key once — surfaces malformed input
      // early and lets libsodium reject anything that isn't a valid X-Wing
      // pubkey before any DB write.
      const publicKeyBytes = importPublicKeyFromBase64(body.public_key);

      // Generate the challenge id up front and bind the HMAC to it before
      // the row is written. A single atomic INSERT avoids the dirty
      // intermediate state of "row exists with empty expectedHmac".
      const challengeId = randomUUID();
      const { ciphertext, expectedHmac } = await createKeyPossessionChallenge(publicKeyBytes, challengeId);
      const expiresAt = new Date(Date.now() + CHALLENGE_TTL_SECONDS * 1000);

      await prisma.keyPossessionChallenge.create({
        data: {
          id: challengeId,
          userId,
          publicKey: body.public_key,
          // libsodium hands back a Uint8Array with an unconstrained buffer
          // generic; Prisma's Bytes input type requires an
          // ArrayBuffer-backed view, so we copy through Buffer.from to
          // land in the right shape.
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

      const received = base64ToUint8(body.response);
      const ok = await verifyChallengeResponse(new Uint8Array(challenge.expectedHmac), received);

      if (!ok) {
        // Don't delete on first miss — the HMAC could be a transport
        // glitch. Keep the row until expiry; the caller can retry with
        // the same id.
        return reply.status(400).send({ code: API_ERROR_CHALLENGE_INVALID_RESPONSE });
      }

      // All writes go through a Serializable transaction so that two
      // concurrent completes for the same user can't both end up
      // creating a fresh active key (PG aborts one with 40001 / P2034).
      // The transaction also re-checks the challenge row by deleting
      // it: a missing row means a parallel call already consumed it,
      // so only one tx can win.
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

            // Rate-limit at completion only: an attacker who can't pass
            // PoP can't burn the user's quota, while honest churners
            // are still bounded. Inside the tx so the count and the
            // create that follows see the same snapshot.
            const windowStart = new Date();
            windowStart.setDate(windowStart.getDate() - RATE_LIMIT_WINDOW_DAYS);
            const recentCreations = await tx.publicKey.count({
              where: { userId, createdAt: { gte: windowStart } },
            });

            if (recentCreations >= RATE_LIMIT_MAX_CREATIONS) {
              return { kind: 'rate_limit' };
            }

            await tx.publicKey.updateMany({
              where: { userId, disabledAt: null },
              data: { disabledAt: new Date() },
            });

            const created = await tx.publicKey.create({
              data: {
                userId,
                publicKey: challenge.publicKey,
              },
            });

            // PoP succeeded → the challenge has done its job and must
            // not be replayed. Deleting inside the tx makes this row
            // act as a mutex against any double-spend of the same id.
            await tx.keyPossessionChallenge.delete({ where: { id: challenge.id } });

            return { kind: 'success', userId: created.userId, publicKey: created.publicKey };
          },
          // Prisma's TransactionIsolationLevel type is a string literal
          // union — passing 'Serializable' directly is fully type-safe.
          { isolationLevel: 'Serializable' },
        );
      } catch (err) {
        if (isSerializationFailure(err)) {
          // Two concurrent completes for the same user; PG aborted ours.
          // The caller can safely retry — the challenge is single-use,
          // so at most one of the racers will eventually succeed.
          return reply.status(409).send({ code: API_ERROR_CONCURRENT_REGISTRATION });
        }
        throw err;
      }

      switch (result.kind) {
        case 'consumed':
          return reply.status(404).send({ code: API_ERROR_CHALLENGE_NOT_FOUND });
        case 'rate_limit':
          return reply.status(429).send({
            code: API_ERROR_RATE_LIMIT_KEYS,
            params: { max: RATE_LIMIT_MAX_CREATIONS, days: RATE_LIMIT_WINDOW_DAYS },
          });
        case 'success':
          return { user_id: result.userId, public_key: result.publicKey };
      }
    },
  });
}
