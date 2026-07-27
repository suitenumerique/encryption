import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client';
import Fastify from 'fastify';
import { randomUUID } from 'node:crypto';

import { generateUserKeyPair, hybridDecapsulate, uint8ToBase64 } from '@encryption/src/crypto';
import { base64ToUint8, exportPublicKeyAsBase64 } from '@encryption/src/crypto/encryption-backup';
import { computeChallengeResponse } from '@encryption/src/crypto/key-possession-challenge';
import { encodeKeyRegistrationPayload, encodePopChallengeMessage } from '@encryption/src/crypto/key-registration';
import { generateSignatureKeyPair, signDetached } from '@encryption/src/crypto/signature';
import { testPrisma, testPrismaClient, useTestDatabase } from '@encryption/src/prisma/testing';
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

// env is mocked so importing the route (which reads the active issuer for the
// `subs=` directory form) does not pull the real env validator under test.
jest.mock('@encryption/src/server/env', () => ({
  env: {
    OIDC_ISSUER: 'https://issuer.example',
  },
}));

// The database is real (in-process Postgres), so registration is exercised
// against the actual unique constraints, joins and cascades. Two tests spy on
// `$transaction` to inject an interleaving PGlite cannot produce (see their
// comments); everything else runs untouched.
jest.mock('@encryption/src/prisma/client', () => ({ prisma: jest.requireActual('@encryption/src/prisma/testing').testPrisma }));

const mockVerifyJWT = jest.fn();

function buildApp() {
  const app = Fastify();

  app.decorate('verifyJWT', mockVerifyJWT);
  app.register(publicKeysRoute);

  return app;
}

const USER_ID = '550e8400-e29b-41d4-a716-446655440000';
const OTHER_USER_ID = '660e8400-e29b-41d4-a716-446655440001';
const UNKNOWN_USER_ID = '770e8400-e29b-41d4-a716-446655440002';
const FAKE_CHALLENGE_ID = '22222222-2222-4222-8222-222222222222';

// `kb`: raw bytes for a stored key/sig column; `kb64`: the base64 the route re-encodes them to.
const kb = (s: string) => Buffer.from(s);
const kb64 = (s: string) => uint8ToBase64(Buffer.from(s));

// ----- Seeding helpers (every test writes the rows it needs, for real) --------

async function seedUser(id: string = USER_ID) {
  return testPrisma.user.create({ data: { id, email: `${id}@example.org` } });
}

async function seedIdentity(
  options: {
    userId?: string;
    signaturePublicKey?: Uint8Array;
    generation?: number;
    disabledAt?: Date | null;
    previousIdentityId?: string | null;
    continuitySignature?: Uint8Array | null;
  } = {}
) {
  return testPrisma.identity.create({
    data: {
      userId: options.userId ?? USER_ID,
      signaturePublicKey: Buffer.from(options.signaturePublicKey ?? kb(`sig-${randomUUID()}`)),
      generation: options.generation ?? 1,
      disabledAt: options.disabledAt ?? null,
      previousIdentityId: options.previousIdentityId ?? null,
      continuitySignature: options.continuitySignature ? Buffer.from(options.continuitySignature) : null,
    },
  });
}

async function seedEncryptionKey(options: {
  userId?: string;
  identityId: string;
  encryptionPublicKey?: Uint8Array;
  keyBindingSignature?: Uint8Array;
  version?: number;
  createdAt?: Date;
  disabledAt?: Date | null;
}) {
  return testPrisma.encryptionKey.create({
    data: {
      userId: options.userId ?? USER_ID,
      identityId: options.identityId,
      encryptionPublicKey: Buffer.from(options.encryptionPublicKey ?? kb(`enc-${randomUUID()}`)),
      keyBindingSignature: Buffer.from(options.keyBindingSignature ?? kb('bind')),
      version: options.version ?? 1,
      createdAt: options.createdAt,
      disabledAt: options.disabledAt ?? null,
    },
  });
}

// A vault with its primary credential: unlock material lives on VaultCredential,
// the keyring row is only the container.
async function seedKeyring(options: { userId?: string; identityId: string; disabledAt?: Date | null }) {
  return testPrisma.vaultKeyring.create({
    data: {
      userId: options.userId ?? USER_ID,
      identityId: options.identityId,
      disabledAt: options.disabledAt ?? null,
      credentials: {
        create: {
          type: 'primary',
          wrappedVrk: 'd3JhcHBlZA==',
          authPublicKey: kb('auth-pub'),
          authPubSig: kb('auth-sig'),
          kdfOps: 3,
          kdfMem: 67108864,
          lang: 'english',
        },
      },
    },
  });
}

// A fully self-consistent, signed registration the way the vault would produce
// it: real keys so the route's binding + signature-PoP checks actually run.
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

// The candidate stashed between init and complete, written for real so the
// complete handler reads exactly what the server would have persisted.
async function seedChallenge(reg: Registration, expectedHmac: Uint8Array, overrides: { userId?: string; expiresAt?: Date } = {}) {
  return testPrisma.keyPossessionChallenge.create({
    data: {
      id: FAKE_CHALLENGE_ID,
      userId: overrides.userId ?? USER_ID,
      encryptionPublicKey: Buffer.from(base64ToUint8(reg.encryptionPublicKey)),
      signaturePublicKey: Buffer.from(base64ToUint8(reg.signaturePublicKey)),
      keyBindingSignature: Buffer.from(base64ToUint8(reg.keyBindingSignature)),
      version: reg.version,
      signedCreatedAt: new Date(reg.createdAtMillis),
      expectedHmac: Buffer.from(expectedHmac),
      expiresAt: overrides.expiresAt ?? new Date(Date.now() + 60_000),
    },
  });
}

describe('public-keys routes', () => {
  useTestDatabase();

  beforeEach(() => {
    jest.restoreAllMocks();
    jest.clearAllMocks();
    // clearAllMocks clears call history but NOT implementations set via
    // mockResolvedValue / mockRejectedValue, so a value from one test would leak
    // into the next.
    mockVerifyJWT.mockReset();
  });

  // ----- GET /api/public-keys ------------------------------------------------

  describe('GET /api/public-keys', () => {
    it('serves the batch listing without a JWT (public directory, fetched tokenless by the vault)', async () => {
      const app = buildApp();
      // Even if JWT verification would reject, this public listing is not gated by
      // it: the vault fetches it during a product-initiated share with no token.
      mockVerifyJWT.mockRejectedValue(Object.assign(new Error('Unauthorized'), { statusCode: 401 }));

      const response = await app.inject({ method: 'GET', url: `/api/public-keys?user_ids=${USER_ID}` });

      expect(response.statusCode).toBe(200);
      expect(mockVerifyJWT).not.toHaveBeenCalled();
    });

    it('returns the full registry record for active (non-disabled) keys', async () => {
      const app = buildApp();
      const createdAt = new Date(1_700_000_000_000);

      await seedUser();
      const identity = await seedIdentity({ signaturePublicKey: kb('sig1') });
      await seedEncryptionKey({
        identityId: identity.id,
        encryptionPublicKey: kb('enc1'),
        keyBindingSignature: kb('bind1'),
        version: 2,
        createdAt,
      });
      // A rotated-away key of the same user must not surface.
      await seedEncryptionKey({ identityId: identity.id, version: 1, disabledAt: new Date() });

      // Another user whose identity is disabled: the encryption key row stays
      // active but the join on the active identity must hide them entirely.
      await seedUser(OTHER_USER_ID);
      const hiddenIdentity = await seedIdentity({ userId: OTHER_USER_ID, disabledAt: new Date() });
      await seedEncryptionKey({ userId: OTHER_USER_ID, identityId: hiddenIdentity.id });

      const response = await app.inject({ method: 'GET', url: `/api/public-keys?user_ids=${USER_ID}&user_ids=${OTHER_USER_ID}` });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).keys).toEqual([
        {
          user_id: USER_ID,
          encryption_public_key: kb64('enc1'),
          // The signature key lives on the joined identity, not the key row.
          signature_public_key: kb64('sig1'),
          key_binding_signature: kb64('bind1'),
          version: 2,
          created_at_millis: createdAt.getTime(),
        },
      ]);
    });

    it('returns empty array for unknown user IDs', async () => {
      const app = buildApp();

      const response = await app.inject({ method: 'GET', url: `/api/public-keys?user_ids=${UNKNOWN_USER_ID}` });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).keys).toHaveLength(0);
    });

    it('resolves subs through oidc_accounts and echoes the matched sub', async () => {
      const app = buildApp();
      const createdAt = new Date(1_700_000_000_000);

      await seedUser();
      // A disabled row under the ACTIVE issuer still resolves: disabledAt
      // blocks authentication, not directory resolution.
      await testPrisma.oidcAccount.create({
        data: { userId: USER_ID, issuer: 'https://issuer.example', subject: 'kc-sub-1', disabledAt: new Date() },
      });
      const identity = await seedIdentity({ signaturePublicKey: kb('sig1') });
      await seedEncryptionKey({
        identityId: identity.id,
        encryptionPublicKey: kb('enc1'),
        keyBindingSignature: kb('bind1'),
        version: 1,
        createdAt,
      });

      const response = await app.inject({ method: 'GET', url: '/api/public-keys?subs=kc-sub-1' });

      expect(response.statusCode).toBe(200);
      const keys = JSON.parse(response.body).keys;
      expect(keys).toHaveLength(1);
      expect(keys[0].user_id).toBe(USER_ID);
      expect(keys[0].sub).toBe('kc-sub-1');
    });

    it('never resolves a sub through a retired issuer (fail-closed after a provider cutover)', async () => {
      const app = buildApp();

      // The DB holds this sub only under a retired issuer, so the issuer-scoped
      // query matches nothing and the sub simply does not resolve, even though the
      // user does have an active key. Matching the retired row would be fail-open:
      // on a cross-issuer sub collision the directory could hand out another
      // human's public key.
      await seedUser();
      await testPrisma.oidcAccount.create({
        data: { userId: USER_ID, issuer: 'https://retired.example', subject: 'recycled-sub' },
      });
      const identity = await seedIdentity();
      await seedEncryptionKey({ identityId: identity.id });

      const response = await app.inject({ method: 'GET', url: '/api/public-keys?subs=recycled-sub' });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).keys).toEqual([]);
    });

    it('echoes one entry PER matched sub when several subs resolve to the same user (email-linked credentials)', async () => {
      const app = buildApp();

      await seedUser();
      await testPrisma.oidcAccount.createMany({
        data: [
          { userId: USER_ID, issuer: 'https://issuer.example', subject: 'kc-sub-old' },
          { userId: USER_ID, issuer: 'https://issuer.example', subject: 'kc-sub-new' },
        ],
      });
      const identity = await seedIdentity();
      await seedEncryptionKey({ identityId: identity.id });

      const response = await app.inject({ method: 'GET', url: '/api/public-keys?subs=kc-sub-old&subs=kc-sub-new' });

      // Both queried subs find their echo; collapsing to one entry would make
      // the other sub read as "no keys" to the caller.
      const keys = JSON.parse(response.body).keys;
      expect(keys.map((k: { user_id: string; sub: string }) => `${k.user_id}|${k.sub}`).sort()).toEqual([
        `${USER_ID}|kc-sub-new`,
        `${USER_ID}|kc-sub-old`,
      ]);
    });

    it('rejects a query mixing user_ids and subs', async () => {
      const app = buildApp();

      await seedUser();
      await testPrisma.oidcAccount.create({ data: { userId: USER_ID, issuer: 'https://issuer.example', subject: 'kc-sub-1' } });
      const identity = await seedIdentity();
      await seedEncryptionKey({ identityId: identity.id });

      const response = await app.inject({
        method: 'GET',
        url: `/api/public-keys?user_ids=${USER_ID}&subs=kc-sub-1`,
      });

      // The bare test app has no ZodError -> 400 mapper (that lives in
      // createServer's error handler); what matters here is that the mixed
      // query is rejected before any record is looked up, even though both
      // forms would individually have matched a real row.
      expect(response.statusCode).toBeGreaterThanOrEqual(400);
      expect(response.body).not.toContain('encryption_public_key');
    });

    it('answers an unmatched sub with an empty list without touching the key table', async () => {
      const app = buildApp();

      await seedUser();
      const identity = await seedIdentity();
      await seedEncryptionKey({ identityId: identity.id });

      const response = await app.inject({ method: 'GET', url: '/api/public-keys?subs=ghost' });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).keys).toHaveLength(0);
    });
  });

  // ----- GET /api/public-keys/:userId ----------------------------------------

  describe('GET /api/public-keys/:userId', () => {
    it('serves the active record with a version ETag and revalidates with 304', async () => {
      const app = buildApp();
      const createdAt = new Date(1_700_000_000_000);

      await seedUser();
      const identity = await seedIdentity({ signaturePublicKey: kb('sig') });
      await seedEncryptionKey({
        identityId: identity.id,
        encryptionPublicKey: kb('enc'),
        keyBindingSignature: kb('bind'),
        version: 3,
        createdAt,
      });

      const first = await app.inject({ method: 'GET', url: `/api/public-keys/${USER_ID}` });
      expect(first.statusCode).toBe(200);
      expect(first.headers.etag).toBe('"v3"');
      expect(first.json()).toEqual({
        user_id: USER_ID,
        encryption_public_key: kb64('enc'),
        signature_public_key: kb64('sig'),
        key_binding_signature: kb64('bind'),
        version: 3,
        created_at_millis: createdAt.getTime(),
      });

      const revalidate = await app.inject({
        method: 'GET',
        url: `/api/public-keys/${USER_ID}`,
        headers: { 'if-none-match': '"v3"' },
      });
      expect(revalidate.statusCode).toBe(304);
    });

    it('404s when the user has no active key', async () => {
      const app = buildApp();

      await seedUser();
      const identity = await seedIdentity();
      await seedEncryptionKey({ identityId: identity.id, disabledAt: new Date() });

      const response = await app.inject({ method: 'GET', url: `/api/public-keys/${USER_ID}` });

      expect(response.statusCode).toBe(404);
    });
  });

  // ----- GET /api/public-keys/:userId/continuity -----------------------------

  describe('GET /api/public-keys/:userId/continuity', () => {
    it('walks the identity chain from the active key back through rotations', async () => {
      const app = buildApp();

      // Active encryption key points at gen-3, which chains gen-2 -> gen-1.
      await seedUser();
      const identity1 = await seedIdentity({ signaturePublicKey: kb('sig1'), generation: 1, disabledAt: new Date() });
      const identity2 = await seedIdentity({
        signaturePublicKey: kb('sig2'),
        generation: 2,
        disabledAt: new Date(),
        previousIdentityId: identity1.id,
        continuitySignature: kb('csig2'),
      });
      const identity3 = await seedIdentity({
        signaturePublicKey: kb('sig3'),
        generation: 3,
        previousIdentityId: identity2.id,
        continuitySignature: kb('csig3'),
      });
      await seedEncryptionKey({ identityId: identity3.id });

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

      await seedUser();
      const identity = await seedIdentity({ signaturePublicKey: kb('sig1') });
      await seedEncryptionKey({ identityId: identity.id });

      const response = await app.inject({ method: 'GET', url: `/api/public-keys/${USER_ID}/continuity` });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ chain: [] });
    });

    it('returns an empty chain when the user has no active key', async () => {
      const app = buildApp();

      await seedUser();

      const response = await app.inject({ method: 'GET', url: `/api/public-keys/${USER_ID}/continuity` });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ chain: [] });
    });

    it('stops at the hop cap even if the chain is longer', async () => {
      const app = buildApp();

      // The head points at itself, so the walk would never end on its own; the
      // cap must bound it to MAX_CONTINUITY_HOPS links.
      await seedUser();
      const identity = await seedIdentity({ signaturePublicKey: kb('head'), generation: 99 });
      await testPrisma.identity.update({
        where: { id: identity.id },
        data: { previousIdentityId: identity.id, continuitySignature: kb('csig') },
      });
      await seedEncryptionKey({ identityId: identity.id });

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

      await seedUser();
      const identity = await seedIdentity();
      const key = await seedEncryptionKey({ identityId: identity.id });
      const keyring = await seedKeyring({ identityId: identity.id });

      const response = await app.inject({ method: 'DELETE', url: '/api/public-keys' });

      expect(response.statusCode).toBe(200);
      // The identity + vault keyring are disabled; the encryption key stays valid.
      expect((await testPrisma.identity.findUnique({ where: { id: identity.id } }))!.disabledAt).toBeInstanceOf(Date);
      expect((await testPrisma.vaultKeyring.findUnique({ where: { id: keyring.id } }))!.disabledAt).toBeInstanceOf(Date);
      expect((await testPrisma.encryptionKey.findUnique({ where: { id: key.id } }))!.disabledAt).toBeNull();
    });

    it('404s when no active identity exists', async () => {
      const app = buildApp();
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });

      await seedUser();
      await seedIdentity({ disabledAt: new Date() });

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

      await seedUser();
      const live = Array.from({ length: 10 }, () => ({ expiresAt: new Date(Date.now() + 60_000) }));
      const expired = Array.from({ length: 2 }, () => ({ expiresAt: new Date(Date.now() - 60_000) }));

      await testPrisma.keyPossessionChallenge.createMany({
        data: [...live, ...expired].map(({ expiresAt }) => ({
          userId: USER_ID,
          encryptionPublicKey: kb(`enc-${randomUUID()}`),
          signaturePublicKey: kb('sig'),
          keyBindingSignature: kb('bind'),
          version: 1,
          signedCreatedAt: new Date(),
          expectedHmac: kb('hmac'),
          expiresAt,
        })),
      });

      const response = await app.inject({ method: 'POST', url: '/api/public-keys/register/init', payload: initPayload(reg) });

      expect(response.statusCode).toBe(429);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_RATE_LIMIT_CHALLENGES);
      // Expired rows are swept, but no new challenge is written when over the cap.
      expect(await testPrisma.keyPossessionChallenge.count()).toBe(10);
      expect(await testPrisma.keyPossessionChallenge.count({ where: { expiresAt: { lt: new Date() } } })).toBe(0);
    });

    it('rejects mismatched user_id vs JWT sub', async () => {
      const app = buildApp();
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });
      const reg = await buildRegistration();

      await seedUser();

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/init',
        payload: { ...initPayload(reg), user_id: UNKNOWN_USER_ID },
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
      const tampered = await buildRegistration(); // different keys, so the signature won't match reg's keys

      await seedUser();

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/init',
        payload: { ...initPayload(reg), key_binding_signature: tampered.keyBindingSignature },
      });

      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_INVALID_KEY_BINDING);
      expect(await testPrisma.keyPossessionChallenge.count()).toBe(0);
    });

    it('writes the challenge atomically and returns a usable ciphertext', async () => {
      const app = buildApp();
      const reg = await buildRegistration();

      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });

      await seedUser();

      const response = await app.inject({ method: 'POST', url: '/api/public-keys/register/init', payload: initPayload(reg) });

      expect(response.statusCode).toBe(200);

      const body = JSON.parse(response.body);
      expect(body.challenge_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(typeof body.ciphertext).toBe('string');

      const stored = await testPrisma.keyPossessionChallenge.findUnique({ where: { id: body.challenge_id } });
      expect(await testPrisma.keyPossessionChallenge.count()).toBe(1);
      expect(stored).not.toBeNull();
      expect(Buffer.from(stored!.signaturePublicKey).equals(Buffer.from(base64ToUint8(reg.signaturePublicKey)))).toBe(true);
      expect(Buffer.from(stored!.encryptionPublicKey).equals(Buffer.from(base64ToUint8(reg.encryptionPublicKey)))).toBe(true);
      expect(stored!.version).toBe(reg.version);
      expect(stored!.userId).toBe(USER_ID);

      // The expectedHmac is what the holder of the ENCRYPTION secret key would
      // produce by decapsulating the returned ciphertext and HMAC'ing the id.
      const ciphertext = Uint8Array.from(atob(body.ciphertext), (c) => c.charCodeAt(0));
      const ss = await hybridDecapsulate(reg.encryption.secretKey, ciphertext);
      const expectedResponse = await computeChallengeResponse(ss, body.challenge_id);
      expect(Buffer.from(stored!.expectedHmac).equals(Buffer.from(expectedResponse))).toBe(true);
    });
  });

  describe('GET /api/public-keys/next', () => {
    it('returns version 1 / generation 1 for a first-time user', async () => {
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });

      await seedUser();

      const res = await buildApp().inject({ method: 'GET', url: '/api/public-keys/next' });

      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ next_version: 1, next_generation: 1 });
    });

    it('counts disabled rows so a reset never reuses a number', async () => {
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });

      // Everything the user ever registered is disabled (a full reset), yet the
      // next numbers must still continue past the highest ones ever used.
      await seedUser();
      const identity1 = await seedIdentity({ generation: 1, disabledAt: new Date() });
      const identity2 = await seedIdentity({ generation: 2, disabledAt: new Date() });
      await seedEncryptionKey({ identityId: identity1.id, version: 1, disabledAt: new Date() });
      await seedEncryptionKey({ identityId: identity2.id, version: 2, disabledAt: new Date() });
      await seedEncryptionKey({ identityId: identity2.id, version: 3, disabledAt: new Date() });

      const res = await buildApp().inject({ method: 'GET', url: '/api/public-keys/next' });

      expect(res.json()).toEqual({ next_version: 4, next_generation: 3 });
    });
  });

  // ----- POST /api/public-keys/register/complete -----------------------------

  describe('POST /api/public-keys/register/complete', () => {
    function setupAuth() {
      mockVerifyJWT.mockImplementation(async (request) => {
        request.userId = USER_ID;
      });
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

      await seedUser();
      await seedUser(OTHER_USER_ID);
      await seedChallenge(reg, new Uint8Array(32), { userId: OTHER_USER_ID });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload('AA==', 'AA=='),
      });

      expect(response.statusCode).toBe(404);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CHALLENGE_NOT_FOUND);
      // Someone else's challenge is never consumed by the probe.
      expect(await testPrisma.keyPossessionChallenge.count()).toBe(1);
    });

    it('returns 410 when the challenge has expired', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration();

      await seedUser();
      await seedChallenge(reg, new Uint8Array(32), { expiresAt: new Date(Date.now() - 1000) });

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload('AA==', 'AA=='),
      });

      expect(response.statusCode).toBe(410);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CHALLENGE_EXPIRED);
      expect(await testPrisma.keyPossessionChallenge.count()).toBe(0);
    });

    it('returns 400 on a bad HMAC and keeps the challenge for retry', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration();

      await seedUser();
      await seedChallenge(reg, new Uint8Array(32).fill(0xab));

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(new Uint8Array(32).fill(0xcd)), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CHALLENGE_INVALID_RESPONSE);
      expect(await testPrisma.keyPossessionChallenge.count()).toBe(1);
      expect(await testPrisma.encryptionKey.count()).toBe(0);
    });

    it('returns 400 when the signature-key proof-of-possession does not verify', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration();
      const ssMock = new Uint8Array(32).fill(0x42);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);

      await seedUser();
      await seedChallenge(reg, expectedHmac);

      // HMAC is valid but the challenge signature is from a DIFFERENT identity.
      const wrongIdentity = await buildRegistration();

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(wrongIdentity)),
      });

      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_INVALID_CHALLENGE_SIGNATURE);
      expect(await testPrisma.keyPossessionChallenge.count()).toBe(1);
      expect(await testPrisma.encryptionKey.count()).toBe(0);
    });

    it('rate-limits at 10 successful PoPs in 30 days inside the transaction', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration(11);
      const ssMock = new Uint8Array(32).fill(0x42);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);

      // Rotation under an existing vault-backed identity (so it passes the
      // no-vault guard and reaches the rate-limit check), with the quota already
      // burnt by 10 registrations inside the window.
      await seedUser();
      const identity = await seedIdentity({ signaturePublicKey: base64ToUint8(reg.signaturePublicKey) });
      await seedKeyring({ identityId: identity.id });

      for (let version = 1; version <= 10; version++) {
        await seedEncryptionKey({ identityId: identity.id, version, disabledAt: version === 10 ? null : new Date() });
      }

      await seedChallenge(reg, expectedHmac);

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
      expect(await testPrisma.encryptionKey.count()).toBe(10);
      expect(await testPrisma.identity.count()).toBe(1);
      expect(await testPrisma.keyPossessionChallenge.count()).toBe(1);
    });

    it('returns 409 on a non-monotonic version (raced another device)', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration(1);
      const ssMock = new Uint8Array(32).fill(0x55);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);

      // Rotation under an existing identity; another device already registered
      // version 1, so the expected next is 2 and the client's version 1 conflicts.
      await seedUser();
      const identity = await seedIdentity({ signaturePublicKey: base64ToUint8(reg.signaturePublicKey) });
      await seedKeyring({ identityId: identity.id });
      await seedEncryptionKey({ identityId: identity.id, version: 1 });

      await seedChallenge(reg, expectedHmac);

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(409);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_KEY_VERSION_CONFLICT);
      expect(await testPrisma.encryptionKey.count()).toBe(1);
    });

    it('returns 404 if the challenge is consumed by a parallel call inside the transaction', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration();
      const ssMock = new Uint8Array(32).fill(0x66);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);

      await seedUser();
      const identity = await seedIdentity({ signaturePublicKey: base64ToUint8(reg.signaturePublicKey) });
      await seedKeyring({ identityId: identity.id });
      await seedChallenge(reg, expectedHmac);

      // This case needs two live sessions: a parallel completer must consume the
      // challenge between our read and our transaction. PGlite multiplexes onto a
      // single backend, so a competitor is queued rather than raced, and we
      // deliberately do not pull in testcontainers/Docker for it. Only the
      // interleaving is injected here: the deletion and the transaction itself
      // both run for real against the database.
      const client = testPrismaClient();

      jest.spyOn(client, '$transaction').mockImplementationOnce((async (...args: unknown[]) => {
        await testPrisma.keyPossessionChallenge.delete({ where: { id: FAKE_CHALLENGE_ID } });

        return (client.$transaction as unknown as (...forwarded: unknown[]) => Promise<unknown>)(...args);
      }) as never);

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(404);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_CHALLENGE_NOT_FOUND);
      expect(await testPrisma.encryptionKey.count()).toBe(0);
    });

    it('returns 409 when PG aborts the transaction with a serialization failure', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration();
      const ssMock = new Uint8Array(32).fill(0x77);
      const expectedHmac = await computeChallengeResponse(ssMock, FAKE_CHALLENGE_ID);

      await seedUser();
      await seedChallenge(reg, expectedHmac);

      // A genuine 40001 needs two live sessions writing the same rows at
      // Serializable. PGlite multiplexes onto a single backend, so a competitor is
      // queued rather than raced and the conflict can never happen; we deliberately
      // do not pull in testcontainers/Docker for it, and raise the error Prisma
      // would surface instead.
      jest.spyOn(testPrismaClient(), '$transaction').mockImplementationOnce((async () => {
        throw new PrismaClientKnownRequestError('serialization_failure', { code: 'P2034', clientVersion: 'test' });
      }) as never);

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

      // No identity for this signature key: a brand-new identity with no vault
      // behind it. /register/complete must refuse (onboard via bootstrap).
      await seedUser();
      await seedChallenge(reg, expectedHmac);

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(409);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_NO_SERVER_VAULT);
      // Nothing is written: not the identity, not the key, not the challenge delete.
      expect(await testPrisma.identity.count()).toBe(0);
      expect(await testPrisma.encryptionKey.count()).toBe(0);
      expect(await testPrisma.keyPossessionChallenge.count()).toBe(1);
    });

    it('rotates the encryption key under the SAME identity without minting a new identity', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration(2); // new encryption key at version 2
      const ss = new Uint8Array(32).fill(0x24);
      const expectedHmac = await computeChallengeResponse(ss, FAKE_CHALLENGE_ID);

      // The identity (signature key) already exists for THIS user, holding the
      // current active version 1, so the expected next version is 2.
      await seedUser();
      const identity = await seedIdentity({ signaturePublicKey: base64ToUint8(reg.signaturePublicKey) });
      await seedKeyring({ identityId: identity.id });
      const previousKey = await seedEncryptionKey({ identityId: identity.id, version: 1 });

      await seedChallenge(reg, expectedHmac);

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body).version).toBe(2);
      expect(JSON.parse(response.body).signature_public_key).toBe(reg.signaturePublicKey);

      // Same identity is reused: no new identity row, key references the existing id.
      expect(await testPrisma.identity.count()).toBe(1);
      const created = await testPrisma.encryptionKey.findUnique({
        where: { encryptionPublicKey: Buffer.from(base64ToUint8(reg.encryptionPublicKey)) },
      });
      expect(created).not.toBeNull();
      expect(created!.identityId).toBe(identity.id);
      expect(created!.version).toBe(2);
      expect(created!.disabledAt).toBeNull();
      // The signed timestamp becomes the row's createdAt, so later verifications keep matching.
      expect(created!.createdAt.getTime()).toBe(reg.createdAtMillis);
      // Exactly one active key remains: the previous one was rotated away.
      expect((await testPrisma.encryptionKey.findUnique({ where: { id: previousKey.id } }))!.disabledAt).toBeInstanceOf(Date);
      expect(await testPrisma.keyPossessionChallenge.count()).toBe(0);
    });

    it('reactivates an already-registered key on restore instead of bumping a version', async () => {
      const app = buildApp();
      setupAuth();
      // Client (re)signs version 6, but the stored row is version 5: restore
      // must return the immutable stored record, not the client's new version.
      const reg = await buildRegistration(6);
      const ss = new Uint8Array(32).fill(0x35);
      const expectedHmac = await computeChallengeResponse(ss, FAKE_CHALLENGE_ID);
      const originalCreatedAt = new Date(1_600_000_000_000);

      await seedUser();
      const identity = await seedIdentity({ signaturePublicKey: base64ToUint8(reg.signaturePublicKey), disabledAt: new Date() });
      await seedEncryptionKey({
        identityId: identity.id,
        encryptionPublicKey: base64ToUint8(reg.encryptionPublicKey),
        keyBindingSignature: base64ToUint8(reg.keyBindingSignature),
        version: 5,
        createdAt: originalCreatedAt,
        disabledAt: new Date(),
      });
      // The identity's (previously disabled) vault keyring, so warm reactivation
      // can flip it back active without a recovery phrase, plus another vault that
      // is currently the active one and must be demoted.
      const keyring = await seedKeyring({ identityId: identity.id, disabledAt: new Date() });
      const otherIdentity = await seedIdentity({ generation: 2 });
      const otherKeyring = await seedKeyring({ identityId: otherIdentity.id });

      await seedChallenge(reg, expectedHmac);

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
      // active one (demote others, enable this identity's keyring), no phrase.
      expect((await testPrisma.vaultKeyring.findUnique({ where: { id: keyring.id } }))!.disabledAt).toBeNull();
      expect((await testPrisma.vaultKeyring.findUnique({ where: { id: otherKeyring.id } }))!.disabledAt).toBeInstanceOf(Date);

      // Reactivation path: no insert, existing rows re-enabled, challenge consumed.
      expect(await testPrisma.encryptionKey.count()).toBe(1);
      expect(await testPrisma.identity.count()).toBe(2);
      const restored = await testPrisma.encryptionKey.findFirst({ where: { userId: USER_ID } });
      expect(restored!.disabledAt).toBeNull();
      expect(restored!.version).toBe(5);
      expect((await testPrisma.identity.findUnique({ where: { id: identity.id } }))!.disabledAt).toBeNull();
      expect(await testPrisma.keyPossessionChallenge.count()).toBe(0);
    });

    it('rejects an encryption key already registered to another user', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration(1);
      const ss = new Uint8Array(32).fill(0x46);
      const expectedHmac = await computeChallengeResponse(ss, FAKE_CHALLENGE_ID);

      await seedUser();
      await seedUser(OTHER_USER_ID);
      const otherIdentity = await seedIdentity({ userId: OTHER_USER_ID });
      await seedEncryptionKey({
        userId: OTHER_USER_ID,
        identityId: otherIdentity.id,
        encryptionPublicKey: base64ToUint8(reg.encryptionPublicKey),
        keyBindingSignature: base64ToUint8(reg.keyBindingSignature),
      });

      await seedChallenge(reg, expectedHmac);

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(409);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_ENCRYPTION_KEY_TAKEN);
      // The victim's row is untouched.
      expect(await testPrisma.encryptionKey.count({ where: { userId: OTHER_USER_ID } })).toBe(1);
      expect(await testPrisma.encryptionKey.count({ where: { userId: USER_ID } })).toBe(0);
    });

    it('rejects an identity (signature) key already registered to another user', async () => {
      const app = buildApp();
      setupAuth();
      const reg = await buildRegistration(1);
      const ss = new Uint8Array(32).fill(0x57);
      const expectedHmac = await computeChallengeResponse(ss, FAKE_CHALLENGE_ID);

      // The encryption key is new, but the identity key belongs to someone else.
      await seedUser();
      await seedUser(OTHER_USER_ID);
      await seedIdentity({ userId: OTHER_USER_ID, signaturePublicKey: base64ToUint8(reg.signaturePublicKey) });

      await seedChallenge(reg, expectedHmac);

      const response = await app.inject({
        method: 'POST',
        url: '/api/public-keys/register/complete',
        payload: completePayload(uint8ToBase64(expectedHmac), await challengeSignature(reg)),
      });

      expect(response.statusCode).toBe(409);
      expect(JSON.parse(response.body).code).toBe(API_ERROR_IDENTITY_TAKEN);
      expect(await testPrisma.identity.count()).toBe(1);
      expect(await testPrisma.encryptionKey.count()).toBe(0);
    });
  });
});
