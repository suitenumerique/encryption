import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client';
import Fastify from 'fastify';

import { generateUserKeyPair, hybridDecapsulate, uint8ToBase64 } from '@encryption/src/crypto';
import { base64ToUint8, exportPublicKeyAsBase64 } from '@encryption/src/crypto/encryption-backup';
import { computeChallengeResponse } from '@encryption/src/crypto/key-possession-challenge';
import { encodeKeyRegistrationPayload, encodePopChallengeMessage } from '@encryption/src/crypto/key-registration';
import { generateSignatureKeyPair, signDetached } from '@encryption/src/crypto/signature';
import { prisma } from '@encryption/src/prisma/client';
import { publicKeysRoute } from '@encryption/src/server/routes/public-keys';
import {
  API_ERROR_CHALLENGE_EXPIRED,
  API_ERROR_CHALLENGE_INVALID_RESPONSE,
  API_ERROR_CHALLENGE_NOT_FOUND,
  API_ERROR_CONCURRENT_REGISTRATION,
  API_ERROR_FORBIDDEN_OTHER_USER,
  API_ERROR_INVALID_CHALLENGE_SIGNATURE,
  API_ERROR_INVALID_KEY_BINDING,
  API_ERROR_KEY_VERSION_CONFLICT,
  API_ERROR_RATE_LIMIT_KEYS,
} from '@encryption/src/shared/error-codes';

const mockTransaction = jest.fn();

jest.mock('@encryption/src/prisma/client', () => ({
  prisma: {
    publicKey: {
      findMany: jest.fn(),
      findFirst: jest.fn(),
      updateMany: jest.fn(),
      count: jest.fn(),
      aggregate: jest.fn(),
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

// A fully self-consistent, signed registration the way the vault would produce
// it — real keys so the route's binding + signature-PoP checks actually run.
async function buildRegistration(version = 1, createdAtMillis: number = Date.now()) {
  const encryption = await generateUserKeyPair();
  const signature = await generateSignatureKeyPair();

  const encryptionPublicKey = exportPublicKeyAsBase64(encryption.publicKey);
  const signaturePublicKey = exportPublicKeyAsBase64(signature.publicKey);

  const message = encodeKeyRegistrationPayload({
    userId: USER_ID,
    version,
    createdAtMillis,
    encryptionPublicKeyWire: base64ToUint8(encryptionPublicKey),
    signaturePublicKeyWire: base64ToUint8(signaturePublicKey),
  });
  const keyBindingSignature = uint8ToBase64(await signDetached(message, signature.secretKey));

  return { encryption, signature, encryptionPublicKey, signaturePublicKey, version, createdAtMillis, keyBindingSignature };
}

type Registration = Awaited<ReturnType<typeof buildRegistration>>;

function initPayload(reg: Registration) {
  return {
    user_id: USER_ID,
    encryption_public_key: reg.encryptionPublicKey,
    signature_public_key: reg.signaturePublicKey,
    version: reg.version,
    created_at_millis: reg.createdAtMillis,
    key_binding_signature: reg.keyBindingSignature,
  };
}

describe('public-keys routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ----- GET /api/public-keys ------------------------------------------------

  describe('GET /api/public-keys', () => {
    it('returns the full registry record for active (non-disabled) keys', async () => {
      const app = buildApp();
      const createdAt = new Date(1_700_000_000_000);
      (mockedPrisma.publicKey.findMany as jest.Mock).mockResolvedValue([
        {
          userId: 'user-1',
          encryptionPublicKey: 'enc1',
          signaturePublicKey: 'sig1',
          keyBindingSignature: 'bind1',
          version: 2,
          createdAt,
        },
      ]);

      const response = await app.inject({ method: 'GET', url: '/api/public-keys?user_ids=user-1' });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).keys).toEqual([
        {
          user_id: 'user-1',
          encryption_public_key: 'enc1',
          signature_public_key: 'sig1',
          key_binding_signature: 'bind1',
          version: 2,
          created_at_millis: createdAt.getTime(),
        },
      ]);
      expect(mockedPrisma.publicKey.findMany).toHaveBeenCalledWith({
        where: { userId: { in: ['user-1'] }, disabledAt: null },
      });
    });

    it('returns empty array for unknown user IDs', async () => {
      const app = buildApp();
      (mockedPrisma.publicKey.findMany as jest.Mock).mockResolvedValue([]);

      const response = await app.inject({ method: 'GET', url: '/api/public-keys?user_ids=unknown-user' });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).keys).toHaveLength(0);
    });
  });

  // ----- GET /api/public-keys/:userId ----------------------------------------

  describe('GET /api/public-keys/:userId', () => {
    it('serves the active record with a version ETag and revalidates with 304', async () => {
      const app = buildApp();
      const createdAt = new Date(1_700_000_000_000);
      (mockedPrisma.publicKey.findFirst as jest.Mock).mockResolvedValue({
        userId: USER_ID,
        encryptionPublicKey: 'enc',
        signaturePublicKey: 'sig',
        keyBindingSignature: 'bind',
        version: 3,
        createdAt,
      });

      const first = await app.inject({ method: 'GET', url: `/api/public-keys/${USER_ID}` });
      expect(first.statusCode).toBe(200);
      expect(first.headers.etag).toBe('"v3"');

      const revalidate = await app.inject({
        method: 'GET',
        url: `/api/public-keys/${USER_ID}`,
        headers: { 'if-none-match': '"v3"' },
      });
      expect(revalidate.statusCode).toBe(304);
    });

    it('404s when the user has no active key', async () => {
      const app = buildApp();
      (mockedPrisma.publicKey.findFirst as jest.Mock).mockResolvedValue(null);

      const response = await app.inject({ method: 'GET', url: `/api/public-keys/${USER_ID}` });

      expect(response.statusCode).toBe(404);
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
      const reg = await buildRegistration();

      const response = await app.inject({ method: 'POST', url: '/api/public-keys/register/init', payload: initPayload(reg) });

      expect(response.statusCode).toBe(401);
    });

    it('rejects mismatched user_id vs JWT sub', async () => {
      const app = buildApp();
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });
      const reg = await buildRegistration();

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/init',
        payload: { ...initPayload(reg), user_id: 'someone-else' },
      });

      expect(response.statusCode).toBe(403);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_FORBIDDEN_OTHER_USER);
    });

    it('rejects a record whose binding signature does not verify', async () => {
      const app = buildApp();
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });
      const reg = await buildRegistration();
      const tampered = await buildRegistration(); // different keys → signature won't match reg's keys

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/init',
        payload: { ...initPayload(reg), key_binding_signature: tampered.keyBindingSignature },
      });

      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_INVALID_KEY_BINDING);
      expect(mockedPrisma.keyPossessionChallenge.create).not.toHaveBeenCalled();
    });

    it('writes the challenge atomically and returns a usable ciphertext', async () => {
      const app = buildApp();
      const reg = await buildRegistration();

      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });

      let createCallArgs: { id: string; expectedHmac: Uint8Array; signaturePublicKey: string; version: number } | null = null;

      (mockedPrisma.keyPossessionChallenge.create as jest.Mock).mockImplementation(async ({ data }) => {
        createCallArgs = {
          id: data.id,
          expectedHmac: data.expectedHmac,
          signaturePublicKey: data.signaturePublicKey,
          version: data.version,
        };
        return { ...data };
      });

      const response = await app.inject({ method: 'POST', url: '/api/public-keys/register/init', payload: initPayload(reg) });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(body.challenge_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(typeof body.ciphertext).toBe('string');

      expect(mockedPrisma.keyPossessionChallenge.create).toHaveBeenCalledTimes(1);
      expect(createCallArgs).not.toBeNull();
      expect(createCallArgs!.id).toBe(body.challenge_id);
      expect(createCallArgs!.signaturePublicKey).toBe(reg.signaturePublicKey);
      expect(createCallArgs!.version).toBe(reg.version);

      // The expectedHmac is what the holder of the ENCRYPTION secret key would
      // produce by decapsulating the returned ciphertext and HMAC'ing the id.
      const ciphertext = Uint8Array.from(atob(body.ciphertext), (c) => c.charCodeAt(0));
      const ss = await hybridDecapsulate(reg.encryption.secretKey, ciphertext);
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

    function challengeRow(reg: Registration, expectedHmac: Uint8Array, overrides: Partial<{ userId: string; expiresAt: Date }> = {}) {
      return {
        id: FAKE_CHALLENGE_ID,
        userId: USER_ID,
        encryptionPublicKey: reg.encryptionPublicKey,
        signaturePublicKey: reg.signaturePublicKey,
        keyBindingSignature: reg.keyBindingSignature,
        version: reg.version,
        signedCreatedAt: new Date(reg.createdAtMillis),
        expectedHmac,
        expiresAt: new Date(Date.now() + 60_000),
        ...overrides,
      };
    }

    async function challengeSignature(reg: Registration) {
      return uint8ToBase64(await signDetached(encodePopChallengeMessage(FAKE_CHALLENGE_ID), reg.signature.secretKey));
    }

    function completePayload(response: string, challenge_signature: string) {
      return { challenge_id: FAKE_CHALLENGE_ID, response, challenge_signature };
    }

    it("returns 404 when the challenge doesn't belong to the caller", async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration();
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(
        challengeRow(reg, new Uint8Array(32), { userId: 'someone-else' })
      );

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload('AA==', 'AA=='),
      });

      expect(response.statusCode).toBe(404);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CHALLENGE_NOT_FOUND);
    });

    it('returns 410 when the challenge has expired', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration();
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(
        challengeRow(reg, new Uint8Array(32), { expiresAt: new Date(Date.now() - 1000) })
      );
      (mockedPrisma.keyPossessionChallenge.deleteMany as jest.Mock).mockResolvedValue({ count: 1 });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload('AA==', 'AA=='),
      });

      expect(response.statusCode).toBe(410);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CHALLENGE_EXPIRED);
    });

    it('returns 400 on a bad HMAC and keeps the challenge for retry', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration();
      const expectedHmac = new Uint8Array(32).fill(0xab);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(challengeRow(reg, expectedHmac));

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(new Uint8Array(32).fill(0xcd)), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CHALLENGE_INVALID_RESPONSE);
      expect(mockedPrisma.keyPossessionChallenge.delete).not.toHaveBeenCalled();
      expect(mockTransaction).not.toHaveBeenCalled();
    });

    it('returns 400 when the signature-key proof-of-possession does not verify', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration();
      const ssMock = new Uint8Array(32).fill(0x42);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(challengeRow(reg, expectedHmac));

      // HMAC is valid but the challenge signature is from a DIFFERENT identity.
      const wrongIdentity = await buildRegistration();

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(wrongIdentity)),
      });

      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_INVALID_CHALLENGE_SIGNATURE);
      expect(mockTransaction).not.toHaveBeenCalled();
    });

    it('rate-limits at 10 successful PoPs in 30 days inside the transaction', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration();
      const ssMock = new Uint8Array(32).fill(0x42);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(challengeRow(reg, expectedHmac));

      mockTransaction.mockImplementation(async (callback: (tx: unknown) => Promise<unknown>, options) => {
        expect(options).toEqual({ isolationLevel: 'Serializable' });

        const tx = {
          keyPossessionChallenge: {
            findUnique: jest.fn().mockResolvedValue(challengeRow(reg, expectedHmac)),
            delete: jest.fn(),
          },
          publicKey: {
            count: jest.fn().mockResolvedValue(10),
            aggregate: jest.fn().mockResolvedValue({ _max: { version: null } }),
            updateMany: jest.fn(),
            create: jest.fn(),
          },
        };

        const result = await callback(tx);

        expect(tx.publicKey.updateMany).not.toHaveBeenCalled();
        expect(tx.publicKey.create).not.toHaveBeenCalled();
        expect(tx.keyPossessionChallenge.delete).not.toHaveBeenCalled();

        return result;
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(429);
      const body = JSON.parse(response.body);
      expect(body.code).toBe(API_ERROR_RATE_LIMIT_KEYS);
      expect(body.params).toEqual({ max: 10, days: 30 });
    });

    it('returns 409 on a non-monotonic version (raced another device)', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration(1);
      const ssMock = new Uint8Array(32).fill(0x55);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(challengeRow(reg, expectedHmac));

      mockTransaction.mockImplementation(async (callback: (tx: unknown) => Promise<unknown>) => {
        const tx = {
          keyPossessionChallenge: { findUnique: jest.fn().mockResolvedValue(challengeRow(reg, expectedHmac)), delete: jest.fn() },
          publicKey: {
            count: jest.fn().mockResolvedValue(0),
            // Another device already registered version 1 → expected next is 2.
            aggregate: jest.fn().mockResolvedValue({ _max: { version: 1 } }),
            updateMany: jest.fn(),
            create: jest.fn(),
          },
        };

        return callback(tx);
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(409);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_KEY_VERSION_CONFLICT);
    });

    it('returns 404 if the challenge is consumed by a parallel call inside the transaction', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration();
      const ssMock = new Uint8Array(32).fill(0x66);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(challengeRow(reg, expectedHmac));

      mockTransaction.mockImplementation(async (callback: (tx: unknown) => Promise<unknown>) => {
        const tx = {
          keyPossessionChallenge: { findUnique: jest.fn().mockResolvedValue(null), delete: jest.fn() },
          publicKey: { count: jest.fn(), aggregate: jest.fn(), updateMany: jest.fn(), create: jest.fn() },
        };

        return callback(tx);
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(404);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CHALLENGE_NOT_FOUND);
    });

    it('returns 409 when PG aborts the transaction with a serialization failure', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration();
      const ssMock = new Uint8Array(32).fill(0x77);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(challengeRow(reg, expectedHmac));

      mockTransaction.mockImplementation(async () => {
        throw new PrismaClientKnownRequestError('serialization_failure', { code: 'P2034', clientVersion: 'test' });
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(409);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CONCURRENT_REGISTRATION);
    });

    it('persists the registry record on successful dual PoP and consumes the challenge', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration(1);
      const ss = new Uint8Array(32).fill(0x99);
      const expectedHmac = await computeChallengeResponse(ss, FAKE_CHALLENGE_ID);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(challengeRow(reg, expectedHmac));

      mockTransaction.mockImplementation(async (callback: (tx: unknown) => Promise<unknown>, options) => {
        expect(options).toEqual({ isolationLevel: 'Serializable' });

        const createdRow = {
          id: 'new-id',
          userId: USER_ID,
          encryptionPublicKey: reg.encryptionPublicKey,
          signaturePublicKey: reg.signaturePublicKey,
          keyBindingSignature: reg.keyBindingSignature,
          version: reg.version,
          createdAt: new Date(reg.createdAtMillis),
        };

        const tx = {
          keyPossessionChallenge: {
            findUnique: jest.fn().mockResolvedValue(challengeRow(reg, expectedHmac)),
            delete: jest.fn().mockResolvedValue({ id: FAKE_CHALLENGE_ID }),
          },
          publicKey: {
            count: jest.fn().mockResolvedValue(0),
            aggregate: jest.fn().mockResolvedValue({ _max: { version: null } }),
            updateMany: jest.fn().mockResolvedValue({ count: 1 }),
            create: jest.fn().mockResolvedValue(createdRow),
          },
        };

        const result = await callback(tx);

        expect(tx.publicKey.updateMany).toHaveBeenCalledWith({
          where: { userId: USER_ID, disabledAt: null },
          data: { disabledAt: expect.any(Date) },
        });
        expect(tx.publicKey.create).toHaveBeenCalledWith({
          data: {
            userId: USER_ID,
            encryptionPublicKey: reg.encryptionPublicKey,
            signaturePublicKey: reg.signaturePublicKey,
            keyBindingSignature: reg.keyBindingSignature,
            version: reg.version,
            createdAt: new Date(reg.createdAtMillis),
          },
        });
        expect(tx.keyPossessionChallenge.delete).toHaveBeenCalledWith({ where: { id: FAKE_CHALLENGE_ID } });

        return result;
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body)).toEqual({
        user_id: USER_ID,
        encryption_public_key: reg.encryptionPublicKey,
        signature_public_key: reg.signaturePublicKey,
        key_binding_signature: reg.keyBindingSignature,
        version: reg.version,
        created_at_millis: reg.createdAtMillis,
      });
    });
  });
});
