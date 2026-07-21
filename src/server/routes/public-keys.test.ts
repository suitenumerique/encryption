import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client';
import Fastify from 'fastify';

import { generateUserKeyPair, hybridDecapsulate, uint8ToBase64 } from '@encryption/src/crypto';
import { base64ToUint8, exportPublicKeyAsBase64 } from '@encryption/src/crypto/encryption-backup';
import { computeChallengeResponse } from '@encryption/src/crypto/key-possession-challenge';
import { encodeKeyRegistrationPayload, encodePopChallengeMessage } from '@encryption/src/crypto/key-registration';
import { generateSignatureKeyPair, signDetached } from '@encryption/src/crypto/signature';
import { prisma } from '@encryption/src/prisma/client';
import { publicKeysRoute } from '@encryption/src/server/routes/public-keys';
import { MAX_CONTINUITY_HOPS } from '@encryption/src/shared/constants';
import {
  API_ERROR_CHALLENGE_EXPIRED,
  API_ERROR_CHALLENGE_INVALID_RESPONSE,
  API_ERROR_CHALLENGE_NOT_FOUND,
  API_ERROR_CONCURRENT_REGISTRATION,
  API_ERROR_ENCRYPTION_KEY_TAKEN,
  API_ERROR_FORBIDDEN_OTHER_USER,
  API_ERROR_IDENTITY_TAKEN,
  API_ERROR_INVALID_CHALLENGE_SIGNATURE,
  API_ERROR_INVALID_KEY_BINDING,
  API_ERROR_KEY_VERSION_CONFLICT,
  API_ERROR_NO_SERVER_VAULT,
  API_ERROR_RATE_LIMIT_CHALLENGES,
  API_ERROR_RATE_LIMIT_KEYS,
} from '@encryption/src/shared/error-codes';

const mockTransaction = jest.fn();

// env is mocked so importing the route (which reads the active issuer for the
// `subs=` directory form) does not pull the real env validator under test.
jest.mock('@encryption/src/server/env', () => ({
  env: {
    OIDC_ISSUER: 'https://issuer.example',
  },
}));

jest.mock('@encryption/src/prisma/client', () => ({
  prisma: {
    encryptionKey: {
      findMany: jest.fn(),
      findFirst: jest.fn(),
      updateMany: jest.fn(),
      count: jest.fn(),
      aggregate: jest.fn(),
    },
    oidcAccount: {
      findMany: jest.fn(),
    },
    identity: {
      aggregate: jest.fn(),
      findUnique: jest.fn(),
      updateMany: jest.fn(),
    },
    vaultKeyring: {
      updateMany: jest.fn(),
    },
    keyPossessionChallenge: {
      create: jest.fn(),
      findUnique: jest.fn(),
      delete: jest.fn(),
      deleteMany: jest.fn(),
      count: jest.fn(),
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

// `kb`: raw bytes for a mock key/sig row; `kb64`: the base64 the route re-encodes them to.
const kb = (s: string) => Buffer.from(s);
const kb64 = (s: string) => uint8ToBase64(Buffer.from(s));

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

// A fully-mocked Prisma transaction client for the complete handler. Defaults
// model a first-time registration (no existing key, no existing identity); each
// test overrides only the fields that matter to it.
function makeTx(
  opts: {
    challenge?: unknown;
    existingRegistration?: unknown;
    existingIdentity?: unknown;
    recentCount?: number;
    maxVersion?: number | null;
    maxGeneration?: number | null;
    createdRegistration?: unknown;
    createdIdentity?: unknown;
    keyring?: unknown;
  } = {}
) {
  return {
    keyPossessionChallenge: {
      findUnique: jest.fn().mockResolvedValue(opts.challenge ?? null),
      delete: jest.fn().mockResolvedValue({}),
    },
    encryptionKey: {
      findUnique: jest.fn().mockResolvedValue(opts.existingRegistration ?? null),
      count: jest.fn().mockResolvedValue(opts.recentCount ?? 0),
      aggregate: jest.fn().mockResolvedValue({ _max: { version: opts.maxVersion ?? null } }),
      create: jest.fn().mockResolvedValue(opts.createdRegistration ?? {}),
      update: jest.fn().mockResolvedValue({}),
      updateMany: jest.fn().mockResolvedValue({ count: 0 }),
    },
    identity: {
      findUnique: jest.fn().mockResolvedValue(opts.existingIdentity ?? null),
      aggregate: jest.fn().mockResolvedValue({ _max: { generation: opts.maxGeneration ?? null } }),
      create: jest.fn().mockResolvedValue(opts.createdIdentity ?? { id: 'identity-id' }),
      update: jest.fn().mockResolvedValue({}),
      updateMany: jest.fn().mockResolvedValue({ count: 0 }),
    },
    // The warm-reactivation path reactivates the identity's vault keyring.
    vaultKeyring: {
      findFirst: jest.fn().mockResolvedValue(opts.keyring ?? null),
      update: jest.fn().mockResolvedValue({}),
      updateMany: jest.fn().mockResolvedValue({ count: 0 }),
    },
  };
}

type MockTx = ReturnType<typeof makeTx>;

describe('public-keys routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // clearAllMocks clears call history but NOT implementations set via
    // mockResolvedValue / mockRejectedValue, so a value from one test would leak
    // into the next. Reset the mocks whose leaked value changes control flow.
    mockVerifyJWT.mockReset();
    (mockedPrisma.keyPossessionChallenge.count as jest.Mock).mockReset();
  });

  // ----- GET /api/public-keys ------------------------------------------------

  describe('GET /api/public-keys', () => {
    it('serves the batch listing without a JWT (public directory, fetched tokenless by the vault)', async () => {
      const app = buildApp();
      // Even if JWT verification would reject, this public listing is not gated by
      // it: the vault fetches it during a product-initiated share with no token.
      mockVerifyJWT.mockRejectedValue(Object.assign(new Error('Unauthorized'), { statusCode: 401 }));
      (mockedPrisma.encryptionKey.findMany as jest.Mock).mockResolvedValue([]);

      const response = await app.inject({ method: 'GET', url: '/api/public-keys?user_ids=550e8400-e29b-41d4-a716-446655440000' });

      expect(response.statusCode).toBe(200);
      expect(mockVerifyJWT).not.toHaveBeenCalled();
    });

    it('returns the full registry record for active (non-disabled) keys', async () => {
      const app = buildApp();
      const createdAt = new Date(1_700_000_000_000);
      (mockedPrisma.encryptionKey.findMany as jest.Mock).mockResolvedValue([
        {
          userId: '550e8400-e29b-41d4-a716-446655440000',
          encryptionPublicKey: kb('enc1'),
          keyBindingSignature: kb('bind1'),
          version: 2,
          createdAt,
          // The signature key lives on the joined identity, not the key row.
          identity: { signaturePublicKey: kb('sig1') },
        },
      ]);

      const response = await app.inject({ method: 'GET', url: '/api/public-keys?user_ids=550e8400-e29b-41d4-a716-446655440000' });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).keys).toEqual([
        {
          user_id: '550e8400-e29b-41d4-a716-446655440000',
          encryption_public_key: kb64('enc1'),
          signature_public_key: kb64('sig1'),
          key_binding_signature: kb64('bind1'),
          version: 2,
          created_at_millis: createdAt.getTime(),
        },
      ]);
      expect(mockedPrisma.encryptionKey.findMany).toHaveBeenCalledWith({
        where: { userId: { in: ['550e8400-e29b-41d4-a716-446655440000'] }, disabledAt: null, identity: { is: { disabledAt: null } } },
        include: { identity: true },
      });
    });

    it('returns empty array for unknown user IDs', async () => {
      const app = buildApp();
      (mockedPrisma.encryptionKey.findMany as jest.Mock).mockResolvedValue([]);

      const response = await app.inject({ method: 'GET', url: '/api/public-keys?user_ids=660e8400-e29b-41d4-a716-446655440001' });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).keys).toHaveLength(0);
    });

    it('resolves subs through oidc_accounts and echoes the matched sub', async () => {
      const app = buildApp();
      const createdAt = new Date(1_700_000_000_000);
      (mockedPrisma.oidcAccount.findMany as jest.Mock).mockResolvedValue([
        // A disabled row under the ACTIVE issuer still resolves: disabledAt
        // blocks authentication, not directory resolution.
        { userId: 'internal-1', subject: 'kc-sub-1', issuer: 'https://issuer.example', disabledAt: new Date() },
      ]);
      (mockedPrisma.encryptionKey.findMany as jest.Mock).mockResolvedValue([
        {
          userId: 'internal-1',
          encryptionPublicKey: kb('enc1'),
          keyBindingSignature: kb('bind1'),
          version: 1,
          createdAt,
          identity: { signaturePublicKey: kb('sig1') },
        },
      ]);

      const response = await app.inject({ method: 'GET', url: '/api/public-keys?subs=kc-sub-1' });

      expect(response.statusCode).toBe(200);
      // Resolution is scoped to the currently configured issuer, always.
      expect(mockedPrisma.oidcAccount.findMany).toHaveBeenCalledWith({
        where: { issuer: 'https://issuer.example', subject: { in: ['kc-sub-1'] } },
      });
      const keys = JSON.parse(response.body).keys;
      expect(keys).toHaveLength(1);
      expect(keys[0].user_id).toBe('internal-1');
      expect(keys[0].sub).toBe('kc-sub-1');
    });

    it('never resolves a sub through a retired issuer (fail-closed after a provider cutover)', async () => {
      const app = buildApp();
      // The DB holds this sub only under a retired issuer, so the issuer-scoped
      // query matches nothing and the sub simply does not resolve. Matching the
      // retired row would be fail-open: on a cross-issuer sub collision the
      // directory could hand out another human's public key.
      (mockedPrisma.oidcAccount.findMany as jest.Mock).mockResolvedValue([]);

      const response = await app.inject({ method: 'GET', url: '/api/public-keys?subs=recycled-sub' });

      expect(mockedPrisma.oidcAccount.findMany).toHaveBeenCalledWith({
        where: { issuer: 'https://issuer.example', subject: { in: ['recycled-sub'] } },
      });
      expect(JSON.parse(response.body).keys).toEqual([]);
      expect(mockedPrisma.encryptionKey.findMany).not.toHaveBeenCalled();
    });

    it('echoes one entry PER matched sub when several subs resolve to the same user (email-linked credentials)', async () => {
      const app = buildApp();
      const createdAt = new Date(1_700_000_000_000);
      (mockedPrisma.oidcAccount.findMany as jest.Mock).mockResolvedValue([
        { userId: 'internal-1', subject: 'kc-sub-old', issuer: 'https://issuer.example', disabledAt: null },
        { userId: 'internal-1', subject: 'kc-sub-new', issuer: 'https://issuer.example', disabledAt: null },
      ]);
      (mockedPrisma.encryptionKey.findMany as jest.Mock).mockResolvedValue([
        {
          userId: 'internal-1',
          encryptionPublicKey: kb('enc1'),
          keyBindingSignature: kb('bind1'),
          version: 1,
          createdAt,
          identity: { signaturePublicKey: kb('sig1') },
        },
      ]);

      const response = await app.inject({ method: 'GET', url: '/api/public-keys?subs=kc-sub-old&subs=kc-sub-new' });

      // Both queried subs find their echo; collapsing to one entry would make
      // the other sub read as "no keys" to the caller.
      const keys = JSON.parse(response.body).keys;
      expect(keys.map((k: { user_id: string; sub: string }) => [k.user_id, k.sub])).toEqual([
        ['internal-1', 'kc-sub-old'],
        ['internal-1', 'kc-sub-new'],
      ]);
    });

    it('rejects a query mixing user_ids and subs', async () => {
      const app = buildApp();

      const response = await app.inject({
        method: 'GET',
        url: '/api/public-keys?user_ids=550e8400-e29b-41d4-a716-446655440000&subs=kc-sub-1',
      });

      // The bare test app has no ZodError -> 400 mapper (that lives in
      // createServer's error handler); what matters here is that the mixed
      // query never reaches the database.
      expect(response.statusCode).toBeGreaterThanOrEqual(400);
      expect(mockedPrisma.encryptionKey.findMany).not.toHaveBeenCalled();
    });

    it('answers an unmatched sub with an empty list without touching the key table', async () => {
      const app = buildApp();
      (mockedPrisma.oidcAccount.findMany as jest.Mock).mockResolvedValue([]);

      const response = await app.inject({ method: 'GET', url: '/api/public-keys?subs=ghost' });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).keys).toHaveLength(0);
      expect(mockedPrisma.encryptionKey.findMany).not.toHaveBeenCalled();
    });
  });

  // ----- GET /api/public-keys/:userId ----------------------------------------

  describe('GET /api/public-keys/:userId', () => {
    it('serves the active record with a version ETag and revalidates with 304', async () => {
      const app = buildApp();
      const createdAt = new Date(1_700_000_000_000);
      (mockedPrisma.encryptionKey.findFirst as jest.Mock).mockResolvedValue({
        userId: USER_ID,
        encryptionPublicKey: kb('enc'),
        keyBindingSignature: kb('bind'),
        version: 3,
        createdAt,
        identity: { signaturePublicKey: kb('sig') },
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
      (mockedPrisma.encryptionKey.findFirst as jest.Mock).mockResolvedValue(null);

      const response = await app.inject({ method: 'GET', url: `/api/public-keys/${USER_ID}` });

      expect(response.statusCode).toBe(404);
    });
  });

  // ----- GET /api/public-keys/:userId/continuity -----------------------------

  describe('GET /api/public-keys/:userId/continuity', () => {
    it('walks the identity chain from the active key back through rotations', async () => {
      const app = buildApp();

      // Active encryption key points at gen-3, which chains gen-2 -> gen-1.
      (mockedPrisma.encryptionKey.findFirst as jest.Mock).mockResolvedValue({
        userId: USER_ID,
        identity: { signaturePublicKey: kb('sig3'), generation: 3, algo: 'ed25519', previousIdentityId: 'id2', continuitySignature: kb('csig3') },
      });
      (mockedPrisma.identity.findUnique as jest.Mock).mockImplementation(async ({ where }: { where: { id: string } }) => {
        if (where.id === 'id2')
          return {
            id: 'id2',
            signaturePublicKey: kb('sig2'),
            generation: 2,
            algo: 'ed25519',
            previousIdentityId: 'id1',
            continuitySignature: kb('csig2'),
          };
        if (where.id === 'id1')
          return { id: 'id1', signaturePublicKey: kb('sig1'), generation: 1, algo: 'ed25519', previousIdentityId: null, continuitySignature: null };

        return null;
      });

      const response = await app.inject({ method: 'GET', url: `/api/public-keys/${USER_ID}/continuity` });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({
        chain: [
          {
            signature_public_key: kb64('sig3'),
            previous_signature_public_key: kb64('sig2'),
            generation: 3,
            algo: 'ed25519',
            continuity_signature: kb64('csig3'),
          },
          {
            signature_public_key: kb64('sig2'),
            previous_signature_public_key: kb64('sig1'),
            generation: 2,
            algo: 'ed25519',
            continuity_signature: kb64('csig2'),
          },
        ],
      });
    });

    it('returns an empty chain when the active identity has no predecessor', async () => {
      const app = buildApp();
      (mockedPrisma.encryptionKey.findFirst as jest.Mock).mockResolvedValue({
        userId: USER_ID,
        identity: { signaturePublicKey: kb('sig1'), generation: 1, algo: 'ed25519', previousIdentityId: null, continuitySignature: null },
      });

      const response = await app.inject({ method: 'GET', url: `/api/public-keys/${USER_ID}/continuity` });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ chain: [] });
      expect(mockedPrisma.identity.findUnique).not.toHaveBeenCalled();
    });

    it('returns an empty chain when the user has no active key', async () => {
      const app = buildApp();
      (mockedPrisma.encryptionKey.findFirst as jest.Mock).mockResolvedValue(null);

      const response = await app.inject({ method: 'GET', url: `/api/public-keys/${USER_ID}/continuity` });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ chain: [] });
    });

    it('stops at the hop cap even if the chain is longer', async () => {
      const app = buildApp();
      // Every identity points at a predecessor, so the walk would never end on
      // its own; the cap must bound it to MAX_CONTINUITY_HOPS links.
      (mockedPrisma.encryptionKey.findFirst as jest.Mock).mockResolvedValue({
        userId: USER_ID,
        identity: { signaturePublicKey: kb('head'), generation: 99, algo: 'ed25519', previousIdentityId: 'prev', continuitySignature: kb('csig') },
      });
      (mockedPrisma.identity.findUnique as jest.Mock).mockResolvedValue({
        id: 'prev',
        signaturePublicKey: kb('prev'),
        generation: 1,
        algo: 'ed25519',
        previousIdentityId: 'prev',
        continuitySignature: kb('csig'),
      });

      const response = await app.inject({ method: 'GET', url: `/api/public-keys/${USER_ID}/continuity` });

      expect(response.statusCode).toBe(200);
      expect(response.json().chain).toHaveLength(MAX_CONTINUITY_HOPS);
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

    it("disables the user's identity and vault keyring (not the encryption key)", async () => {
      const app = buildApp();
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });
      mockTransaction.mockImplementation(async (ops: Promise<unknown>[]) => Promise.all(ops));
      (mockedPrisma.identity.updateMany as jest.Mock).mockResolvedValue({ count: 1 });
      (mockedPrisma.vaultKeyring.updateMany as jest.Mock).mockResolvedValue({ count: 1 });

      const response = await app.inject({ method: 'DELETE', url: '/api/public-keys' });

      expect(response.statusCode).toBe(200);
      // The identity + vault keyring are disabled; the encryption key stays valid.
      expect(mockedPrisma.identity.updateMany).toHaveBeenCalledWith({
        where: { userId: USER_ID, disabledAt: null },
        data: { disabledAt: expect.any(Date) },
      });
      expect(mockedPrisma.vaultKeyring.updateMany).toHaveBeenCalledWith({
        where: { userId: USER_ID, disabledAt: null },
        data: { disabledAt: expect.any(Date) },
      });
      expect(mockedPrisma.encryptionKey.updateMany).not.toHaveBeenCalled();
    });

    it('404s when no active identity exists', async () => {
      const app = buildApp();
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });
      mockTransaction.mockImplementation(async (ops: Promise<unknown>[]) => Promise.all(ops));
      (mockedPrisma.identity.updateMany as jest.Mock).mockResolvedValue({ count: 0 });
      (mockedPrisma.vaultKeyring.updateMany as jest.Mock).mockResolvedValue({ count: 0 });

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

    it('rejects with 429 when the user already holds the max outstanding challenges', async () => {
      const app = buildApp();
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });
      const reg = await buildRegistration();

      (mockedPrisma.keyPossessionChallenge.deleteMany as jest.Mock).mockResolvedValue({ count: 0 });
      (mockedPrisma.keyPossessionChallenge.count as jest.Mock).mockResolvedValue(10);

      const response = await app.inject({ method: 'POST', url: '/api/public-keys/register/init', payload: initPayload(reg) });

      expect(response.statusCode).toBe(429);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_RATE_LIMIT_CHALLENGES);
      // Expired rows are swept, but no new challenge is written when over the cap.
      expect(mockedPrisma.keyPossessionChallenge.deleteMany).toHaveBeenCalledWith({
        where: { userId: USER_ID, expiresAt: { lt: expect.any(Date) } },
      });
      expect(mockedPrisma.keyPossessionChallenge.create).not.toHaveBeenCalled();
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
        payload: { ...initPayload(reg), user_id: '770e8400-e29b-41d4-a716-446655440002' },
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

      let createCallArgs: { id: string; expectedHmac: Uint8Array; signaturePublicKey: Uint8Array; version: number } | null = null;

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
      expect(Buffer.from(createCallArgs!.signaturePublicKey).equals(Buffer.from(base64ToUint8(reg.signaturePublicKey)))).toBe(true);
      expect(createCallArgs!.version).toBe(reg.version);

      // The expectedHmac is what the holder of the ENCRYPTION secret key would
      // produce by decapsulating the returned ciphertext and HMAC'ing the id.
      const ciphertext = Uint8Array.from(atob(body.ciphertext), (c) => c.charCodeAt(0));
      const ss = await hybridDecapsulate(reg.encryption.secretKey, ciphertext);
      const expectedResponse = await computeChallengeResponse(ss, body.challenge_id);
      expect(Buffer.from(createCallArgs!.expectedHmac).equals(Buffer.from(expectedResponse))).toBe(true);
    });
  });

  describe('GET /api/public-keys/next', () => {
    it('returns version 1 / generation 1 for a first-time user', async () => {
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });
      (mockedPrisma.encryptionKey.aggregate as jest.Mock).mockResolvedValue({ _max: { version: null } });
      (mockedPrisma.identity.aggregate as jest.Mock).mockResolvedValue({ _max: { generation: null } });

      const res = await buildApp().inject({ method: 'GET', url: '/api/public-keys/next' });

      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ next_version: 1, next_generation: 1 });
    });

    it('counts disabled rows so a reset never reuses a number', async () => {
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });
      (mockedPrisma.encryptionKey.aggregate as jest.Mock).mockResolvedValue({ _max: { version: 3 } });
      (mockedPrisma.identity.aggregate as jest.Mock).mockResolvedValue({ _max: { generation: 2 } });

      const res = await buildApp().inject({ method: 'GET', url: '/api/public-keys/next' });

      expect(res.json()).toEqual({ next_version: 4, next_generation: 3 });
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
        encryptionPublicKey: base64ToUint8(reg.encryptionPublicKey),
        signaturePublicKey: base64ToUint8(reg.signaturePublicKey),
        keyBindingSignature: base64ToUint8(reg.keyBindingSignature),
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

      let capturedTx: MockTx | null = null;

      mockTransaction.mockImplementation(async (callback: (tx: MockTx) => Promise<unknown>, options) => {
        expect(options).toEqual({ isolationLevel: 'Serializable' });

        capturedTx = makeTx({
          challenge: challengeRow(reg, expectedHmac),
          // Rotation under an existing vault-backed identity (so it passes the
          // no-vault guard and reaches the rate-limit check).
          existingIdentity: { id: 'identity-1', userId: USER_ID, signaturePublicKey: base64ToUint8(reg.signaturePublicKey), disabledAt: null },
          recentCount: 10,
        });

        return callback(capturedTx);
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

      // No writes on a rate-limited completion.
      expect(capturedTx!.encryptionKey.create).not.toHaveBeenCalled();
      expect(capturedTx!.identity.create).not.toHaveBeenCalled();
      expect(capturedTx!.keyPossessionChallenge.delete).not.toHaveBeenCalled();
    });

    it('returns 409 on a non-monotonic version (raced another device)', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration(1);
      const ssMock = new Uint8Array(32).fill(0x55);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(challengeRow(reg, expectedHmac));

      mockTransaction.mockImplementation(async (callback: (tx: MockTx) => Promise<unknown>) =>
        // Rotation under an existing identity; another device already registered
        // version 1 → expected next is 2, so the client's version 1 conflicts.
        callback(
          makeTx({
            challenge: challengeRow(reg, expectedHmac),
            existingIdentity: { id: 'identity-1', userId: USER_ID, signaturePublicKey: base64ToUint8(reg.signaturePublicKey), disabledAt: null },
            maxVersion: 1,
          })
        )
      );

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

      // Challenge already consumed by a parallel completer inside the tx.
      mockTransaction.mockImplementation(async (callback: (tx: MockTx) => Promise<unknown>) => callback(makeTx({ challenge: null })));

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

    it('refuses to mint a fresh (never-registered) identity: first registration must go through bootstrap', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration(1);
      const ss = new Uint8Array(32).fill(0x99);
      const expectedHmac = await computeChallengeResponse(ss, FAKE_CHALLENGE_ID);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(challengeRow(reg, expectedHmac));

      let capturedTx: MockTx | null = null;

      mockTransaction.mockImplementation(async (callback: (tx: MockTx) => Promise<unknown>, options) => {
        expect(options).toEqual({ isolationLevel: 'Serializable' });

        // No existing identity for this signature key: a brand-new identity with
        // no vault behind it. /register/complete must refuse (onboard via bootstrap).
        capturedTx = makeTx({ challenge: challengeRow(reg, expectedHmac) });

        return callback(capturedTx);
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(409);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_NO_SERVER_VAULT);
      // Nothing is written: not the identity, not the key, not the challenge delete.
      expect(capturedTx!.identity.create).not.toHaveBeenCalled();
      expect(capturedTx!.encryptionKey.create).not.toHaveBeenCalled();
      expect(capturedTx!.keyPossessionChallenge.delete).not.toHaveBeenCalled();
    });

    it('rotates the encryption key under the SAME identity without minting a new identity', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration(2); // new encryption key at version 2
      const ss = new Uint8Array(32).fill(0x24);
      const expectedHmac = await computeChallengeResponse(ss, FAKE_CHALLENGE_ID);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(challengeRow(reg, expectedHmac));

      let capturedTx: MockTx | null = null;

      mockTransaction.mockImplementation(async (callback: (tx: MockTx) => Promise<unknown>) => {
        capturedTx = makeTx({
          challenge: challengeRow(reg, expectedHmac),
          // The identity (signature key) already exists for THIS user.
          existingIdentity: { id: 'identity-1', userId: USER_ID, signaturePublicKey: base64ToUint8(reg.signaturePublicKey), disabledAt: null },
          maxVersion: 1, // current active version → expected next is 2
          createdRegistration: {
            id: 'reg-2',
            userId: USER_ID,
            encryptionPublicKey: base64ToUint8(reg.encryptionPublicKey),
            keyBindingSignature: base64ToUint8(reg.keyBindingSignature),
            version: reg.version,
            createdAt: new Date(reg.createdAtMillis),
            identity: { signaturePublicKey: base64ToUint8(reg.signaturePublicKey) },
          },
        });

        return callback(capturedTx);
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).version).toBe(2);
      expect(JSON.parse(response.body).signature_public_key).toBe(reg.signaturePublicKey);

      // Same identity is reused: no new identity row, key references the existing id.
      expect(capturedTx!.identity.create).not.toHaveBeenCalled();
      expect(capturedTx!.encryptionKey.create).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ identityId: 'identity-1', version: 2 }) })
      );
    });

    it('reactivates an already-registered key on restore instead of bumping a version', async () => {
      const app = buildApp();
      setupAuth();
      // Client (re)signs version 6, but the stored row is version 5 — restore
      // must return the immutable stored record, not the client's new version.
      const reg = await buildRegistration(6);
      const ss = new Uint8Array(32).fill(0x35);
      const expectedHmac = await computeChallengeResponse(ss, FAKE_CHALLENGE_ID);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(challengeRow(reg, expectedHmac));

      const originalCreatedAt = new Date(1_600_000_000_000);
      let capturedTx: MockTx | null = null;

      mockTransaction.mockImplementation(async (callback: (tx: MockTx) => Promise<unknown>) => {
        capturedTx = makeTx({
          challenge: challengeRow(reg, expectedHmac),
          existingRegistration: {
            id: 'reg-existing',
            userId: USER_ID,
            identityId: 'identity-1',
            encryptionPublicKey: base64ToUint8(reg.encryptionPublicKey),
            keyBindingSignature: base64ToUint8(reg.keyBindingSignature),
            version: 5,
            createdAt: originalCreatedAt,
            identity: { signaturePublicKey: base64ToUint8(reg.signaturePublicKey) },
          },
          // The identity's (previously disabled) vault keyring, so warm
          // reactivation can flip it back active without a recovery phrase.
          keyring: { id: 'keyring-1', userId: USER_ID, identityId: 'identity-1', disabledAt: new Date() },
        });

        return callback(capturedTx);
      });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.version).toBe(5); // stored version, NOT the client's 6
      expect(body.created_at_millis).toBe(originalCreatedAt.getTime());

      // Warm reactivation also brings the identity's vault keyring back as the
      // active one (demote others, enable this identity's keyring) — no phrase.
      expect(capturedTx!.vaultKeyring.updateMany).toHaveBeenCalledWith({
        where: { userId: USER_ID, disabledAt: null },
        data: { disabledAt: expect.any(Date) },
      });
      expect(capturedTx!.vaultKeyring.update).toHaveBeenCalledWith({ where: { id: 'keyring-1' }, data: { disabledAt: null } });

      // Reactivation path: no insert, existing row re-enabled, challenge consumed.
      expect(capturedTx!.encryptionKey.create).not.toHaveBeenCalled();
      expect(capturedTx!.identity.create).not.toHaveBeenCalled();
      expect(capturedTx!.encryptionKey.update).toHaveBeenCalledWith({
        where: { id: 'reg-existing' },
        data: { disabledAt: null },
      });
      expect(capturedTx!.keyPossessionChallenge.delete).toHaveBeenCalledWith({ where: { id: FAKE_CHALLENGE_ID } });
    });

    it('rejects an encryption key already registered to another user', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration(1);
      const ss = new Uint8Array(32).fill(0x46);
      const expectedHmac = await computeChallengeResponse(ss, FAKE_CHALLENGE_ID);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(challengeRow(reg, expectedHmac));

      mockTransaction.mockImplementation(async (callback: (tx: MockTx) => Promise<unknown>) =>
        callback(
          makeTx({
            challenge: challengeRow(reg, expectedHmac),
            existingRegistration: {
              id: 'reg-other',
              userId: 'someone-else',
              identityId: 'identity-other',
              encryptionPublicKey: base64ToUint8(reg.encryptionPublicKey),
              keyBindingSignature: base64ToUint8(reg.keyBindingSignature),
              version: 1,
              createdAt: new Date(),
              identity: { signaturePublicKey: base64ToUint8(reg.signaturePublicKey) },
            },
          })
        )
      );

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(409);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_ENCRYPTION_KEY_TAKEN);
    });

    it('rejects an identity (signature) key already registered to another user', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration(1);
      const ss = new Uint8Array(32).fill(0x57);
      const expectedHmac = await computeChallengeResponse(ss, FAKE_CHALLENGE_ID);
      (mockedPrisma.keyPossessionChallenge.findUnique as jest.Mock).mockResolvedValue(challengeRow(reg, expectedHmac));

      mockTransaction.mockImplementation(async (callback: (tx: MockTx) => Promise<unknown>) =>
        callback(
          makeTx({
            challenge: challengeRow(reg, expectedHmac),
            // Encryption key is new, but the identity key belongs to someone else.
            existingIdentity: {
              id: 'identity-other',
              userId: 'someone-else',
              signaturePublicKey: base64ToUint8(reg.signaturePublicKey),
              disabledAt: null,
            },
          })
        )
      );

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(409);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_IDENTITY_TAKEN);
    });
  });
});
