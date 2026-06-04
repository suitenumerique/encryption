import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client';
import Fastify from 'fastify';

import { generateUserKeyPair, hybridDecapsulate, uint8ToBase64 } from '@encryption/src/crypto';
import { exportPublicKeyAsBase64 } from '@encryption/src/crypto/encryption-backup';
import { computeChallengeResponse } from '@encryption/src/crypto/key-possession-challenge';
import { prisma } from '@encryption/src/prisma/client';
import { publicKeysRoute } from '@encryption/src/server/routes/public-keys';
import {
  API_ERROR_CHALLENGE_EXPIRED,
  API_ERROR_CHALLENGE_INVALID_RESPONSE,
  API_ERROR_CHALLENGE_NOT_FOUND,
  API_ERROR_CONCURRENT_REGISTRATION,
  API_ERROR_FORBIDDEN_OTHER_USER,
  API_ERROR_RATE_LIMIT_KEYS,
} from '@encryption/src/shared/error-codes';

const mockTransaction = jest.fn();

jest.mock('@encryption/src/prisma/client', () => ({
  prisma: {
    publicKey: {
      findMany: jest.fn(),
      updateMany: jest.fn(),
      count: jest.fn(),
    },
    keyPossessionChallenge: {
      create: jest.fn(),
      findUnique: jest.fn(),
      delete: jest.fn(),
      deleteMany: jest.fn(),
    },
    $transaction: (...args: unknown[]) => mockTransaction(...args),
  },
}));

const mockVerifyJWT = jest.fn();

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

function buildApp() {
  const app = Fastify();

  app.decorate('verifyJWT', mockVerifyJWT);
  app.register(publicKeysRoute);

  return app;
}

const USER_ID = '550e8400-e29b-41d4-a716-446655440000';

describe('public-keys routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ----- GET /api/public-keys ------------------------------------------------

  describe('GET /api/public-keys', () => {
    it('returns only active (non-disabled) public keys', async () => {
      const app = buildApp();
      (mockedPrisma.publicKey.findMany as jest.Mock).mockResolvedValue([
        { userId: 'user-1', publicKey: 'pk1' },
        { userId: 'user-2', publicKey: 'pk2' },
      ]);

      const response = await app.inject({
        method: 'GET',
        url: '/api/public-keys?user_ids=user-1,user-2',
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(body.keys).toEqual([
        { user_id: 'user-1', public_key: 'pk1' },
        { user_id: 'user-2', public_key: 'pk2' },
      ]);
      expect(body.keys[0].algorithm).toBeUndefined();

      expect(mockedPrisma.publicKey.findMany).toHaveBeenCalledWith({
        where: {
          userId: { in: ['user-1', 'user-2'] },
          disabledAt: null,
        },
      });
    });

    it('returns empty array for unknown user IDs', async () => {
      const app = buildApp();
      (mockedPrisma.publicKey.findMany as jest.Mock).mockResolvedValue([]);

      const response = await app.inject({
        method: 'GET',
        url: '/api/public-keys?user_ids=unknown-user',
      });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).keys).toHaveLength(0);
    });
  });

  // ----- DELETE /api/public-keys ---------------------------------------------

  describe('DELETE /api/public-keys', () => {
    it('rejects requests without JWT', async () => {
      const app = buildApp();
      mockVerifyJWT.mockRejectedValue(Object.assign(new Error('Unauthorized'), { statusCode: 401 }));

      const response = await app.inject({ method: 'DELETE', url: '/api/public-keys' });

      expect(response.statusCode).toBe(401);
    });

    it("disables the user's active key", async () => {
      const app = buildApp();
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });
      (mockedPrisma.publicKey.updateMany as jest.Mock).mockResolvedValue({ count: 1 });

      const response = await app.inject({ method: 'DELETE', url: '/api/public-keys' });

      expect(response.statusCode).toBe(200);
      expect(mockedPrisma.publicKey.updateMany).toHaveBeenCalledWith({
        where: { userId: USER_ID, disabledAt: null },
        data: { disabledAt: expect.any(Date) },
      });
    });

    it('404s when no active key exists', async () => {
      const app = buildApp();
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });
      (mockedPrisma.publicKey.updateMany as jest.Mock).mockResolvedValue({ count: 0 });

      const response = await app.inject({ method: 'DELETE', url: '/api/public-keys' });

      expect(response.statusCode).toBe(404);
    });
  });

  // ----- POST /api/public-keys/register/init ---------------------------------

  describe('POST /api/public-keys/register/init', () => {
    it('rejects requests without JWT', async () => {
      const app = buildApp();
      mockVerifyJWT.mockRejectedValue(Object.assign(new Error('Unauthorized'), { statusCode: 401 }));

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/init',
        payload: { user_id: USER_ID, public_key: 'AA==' },
      });

      expect(response.statusCode).toBe(401);
    });

    it('rejects mismatched user_id vs JWT sub', async () => {
      const app = buildApp();
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/init',
        payload: { user_id: 'someone-else', public_key: 'AA==' },
      });

      expect(response.statusCode).toBe(403);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_FORBIDDEN_OTHER_USER);
    });

    it('writes the challenge atomically and returns a usable ciphertext', async () => {
      const app = buildApp();
      const keyPair = await generateUserKeyPair();
      const publicKeyB64 = exportPublicKeyAsBase64(keyPair.publicKey);

      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });

      let createCallArgs: { id: string; expectedHmac: Uint8Array } | null = null;

      (mockedPrisma.keyPossessionChallenge.create as jest.Mock).mockImplementation(async ({ data }) => {
        createCallArgs = { id: data.id, expectedHmac: data.expectedHmac };
        return { ...data };
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/init',
        payload: { user_id: USER_ID, public_key: publicKeyB64 },
      });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(body.challenge_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(typeof body.ciphertext).toBe('string');

      // One DB write for the whole init — no create-then-update.
      expect(mockedPrisma.keyPossessionChallenge.create).toHaveBeenCalledTimes(1);

      // The expectedHmac stored in DB is what the holder of sk would produce
      // by decapsulating the returned ciphertext and HMAC'ing the challenge id.
      expect(createCallArgs).not.toBeNull();
      expect(createCallArgs!.id).toBe(body.challenge_id);

      const ciphertext = Uint8Array.from(atob(body.ciphertext), (c) => c.charCodeAt(0));
      const ss = await hybridDecapsulate(keyPair.secretKey, ciphertext);
      const expectedResponse = await computeChallengeResponse(ss, body.challenge_id);
      expect(Buffer.from(createCallArgs!.expectedHmac).equals(Buffer.from(expectedResponse))).toBe(true);
    });
  });

  // ----- POST /api/public-keys/register/complete -----------------------------

  describe('POST /api/public-keys/register/complete', () => {
    const FAKE_CHALLENGE_ID = '22222222-2222-4222-8222-222222222222';

    function setupAuth() {
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });
    }

    function fakeChallengeRow(overrides: Partial<{ userId: string; expectedHmac: Uint8Array; expiresAt: Date; publicKey: string }> = {}) {
      return {
        id: FAKE_CHALLENGE_ID,
        userId: USER_ID,
        publicKey: 'pk',
        expectedHmac: new Uint8Array(32),
        expiresAt: new Date(Date.now() + 60_000),
        ...overrides,
      };
    }

    it("returns 404 when the challenge doesn't belong to the caller", async () => {
      const app = buildApp();
      setupAuth();
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(
        fakeChallengeRow({ userId: 'someone-else' }),
      );

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: { challenge_id: FAKE_CHALLENGE_ID, response: 'AA==' },
      });

      expect(response.statusCode).toBe(404);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CHALLENGE_NOT_FOUND);
    });

    it('returns 410 when the challenge has expired', async () => {
      const app = buildApp();
      setupAuth();
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(
        fakeChallengeRow({ expiresAt: new Date(Date.now() - 1000) }),
      );
      (mockedPrisma.keyPossessionChallenge.deleteMany as jest.Mock).mockResolvedValue({ count: 1 });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: { challenge_id: FAKE_CHALLENGE_ID, response: 'AA==' },
      });

      expect(response.statusCode).toBe(410);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CHALLENGE_EXPIRED);
    });

    it('returns 400 on a bad HMAC and keeps the challenge for retry', async () => {
      const app = buildApp();
      setupAuth();

      const expectedHmac = new Uint8Array(32).fill(0xab);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(fakeChallengeRow({ expectedHmac }));

      const wrongResponse = uint8ToBase64(new Uint8Array(32).fill(0xcd));

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: { challenge_id: FAKE_CHALLENGE_ID, response: wrongResponse },
      });

      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CHALLENGE_INVALID_RESPONSE);
      expect(mockedPrisma.keyPossessionChallenge.delete).not.toHaveBeenCalled();
      // No transaction was started for an invalid HMAC.
      expect(mockTransaction).not.toHaveBeenCalled();
    });

    it('rate-limits at 10 successful PoPs in 30 days inside the transaction', async () => {
      const app = buildApp();
      setupAuth();
      const ssMock = new Uint8Array(32).fill(0x42);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);

      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(fakeChallengeRow({ expectedHmac }));

      mockTransaction.mockImplementation(async (callback: (tx: unknown) => Promise<unknown>, options) => {
        // The complete handler must request Serializable isolation
        expect(options).toEqual({ isolationLevel: 'Serializable' });

        const tx = {
          keyPossessionChallenge: {
            findUnique: jest.fn().mockResolvedValue(fakeChallengeRow({ expectedHmac })),
            delete: jest.fn(),
          },
          publicKey: {
            count: jest.fn().mockResolvedValue(10), // at the limit
            updateMany: jest.fn(),
            create: jest.fn(),
          },
        };

        const result = await callback(tx);

        // Hitting rate limit must NOT touch any write
        expect(tx.publicKey.updateMany).not.toHaveBeenCalled();
        expect(tx.publicKey.create).not.toHaveBeenCalled();
        expect(tx.keyPossessionChallenge.delete).not.toHaveBeenCalled();

        return result;
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: { challenge_id: FAKE_CHALLENGE_ID, response: uint8ToBase64(expectedHmac) },
      });

      expect(response.statusCode).toBe(429);

      const body = JSON.parse(response.body);
      expect(body.code).toBe(API_ERROR_RATE_LIMIT_KEYS);
      expect(body.params).toEqual({ max: 10, days: 30 });
    });

    it('returns 404 if the challenge is consumed by a parallel call inside the transaction', async () => {
      const app = buildApp();
      setupAuth();
      const ssMock = new Uint8Array(32).fill(0x66);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);

      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(fakeChallengeRow({ expectedHmac }));

      mockTransaction.mockImplementation(async (callback: (tx: unknown) => Promise<unknown>) => {
        const tx = {
          keyPossessionChallenge: {
            // Concurrent caller already consumed the challenge — re-read sees nothing
            findUnique: jest.fn().mockResolvedValue(null),
            delete: jest.fn(),
          },
          publicKey: { count: jest.fn(), updateMany: jest.fn(), create: jest.fn() },
        };

        return callback(tx);
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: { challenge_id: FAKE_CHALLENGE_ID, response: uint8ToBase64(expectedHmac) },
      });

      expect(response.statusCode).toBe(404);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CHALLENGE_NOT_FOUND);
    });

    it('returns 409 when PG aborts the transaction with a serialization failure', async () => {
      const app = buildApp();
      setupAuth();
      const ssMock = new Uint8Array(32).fill(0x77);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);

      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(fakeChallengeRow({ expectedHmac }));

      mockTransaction.mockImplementation(async () => {
        const err = new PrismaClientKnownRequestError('serialization_failure', {
          code: 'P2034',
          clientVersion: 'test',
        });
        throw err;
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: { challenge_id: FAKE_CHALLENGE_ID, response: uint8ToBase64(expectedHmac) },
      });

      expect(response.statusCode).toBe(409);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CONCURRENT_REGISTRATION);
    });

    it('persists the public key on successful PoP and consumes the challenge', async () => {
      const app = buildApp();
      setupAuth();
      const keyPair = await generateUserKeyPair();
      const publicKeyB64 = exportPublicKeyAsBase64(keyPair.publicKey);
      const ss = new Uint8Array(32).fill(0x99);
      const expectedHmac = await computeChallengeResponse(ss, FAKE_CHALLENGE_ID);

      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(
        fakeChallengeRow({ expectedHmac, publicKey: publicKeyB64 }),
      );

      mockTransaction.mockImplementation(async (callback: (tx: unknown) => Promise<unknown>, options) => {
        // Serializable isolation must be requested
        expect(options).toEqual({ isolationLevel: 'Serializable' });

        const tx = {
          keyPossessionChallenge: {
            findUnique: jest.fn().mockResolvedValue(
              fakeChallengeRow({ expectedHmac, publicKey: publicKeyB64 }),
            ),
            delete: jest.fn().mockResolvedValue({ id: FAKE_CHALLENGE_ID }),
          },
          publicKey: {
            count: jest.fn().mockResolvedValue(0),
            updateMany: jest.fn().mockResolvedValue({ count: 1 }),
            create: jest.fn().mockResolvedValue({ id: 'new-id', userId: USER_ID, publicKey: publicKeyB64 }),
          },
        };

        const result = await callback(tx);

        expect(tx.publicKey.updateMany).toHaveBeenCalledWith({
          where: { userId: USER_ID, disabledAt: null },
          data: { disabledAt: expect.any(Date) },
        });
        expect(tx.publicKey.create).toHaveBeenCalledWith({
          data: { userId: USER_ID, publicKey: publicKeyB64 },
        });
        expect(tx.keyPossessionChallenge.delete).toHaveBeenCalledWith({ where: { id: FAKE_CHALLENGE_ID } });

        return result;
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: { challenge_id: FAKE_CHALLENGE_ID, response: uint8ToBase64(expectedHmac) },
      });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body)).toEqual({ user_id: USER_ID, public_key: publicKeyB64 });
    });
  });
});
