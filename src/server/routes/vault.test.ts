import Fastify from 'fastify';
import { randomBytes } from 'node:crypto';

import { uint8ToBase64 } from '@encryption/src/crypto';
import { base64ToUint8, exportPublicKeyAsBase64 } from '@encryption/src/crypto/encryption-backup';
import { encodeIdentityContinuityPayload, encodePopChallengeMessage } from '@encryption/src/crypto/key-registration';
import { REQUEST_SIG_HEADER, signRequestProof } from '@encryption/src/crypto/request-proof';
import { generateSignatureKeyPair, signDetached } from '@encryption/src/crypto/signature';
import { buildManifest, signManifest } from '@encryption/src/crypto/vault-manifest';
import { deriveKek, deriveVaultAuthKeyPair, signAuthPublicKeyBinding, signVaultChallenge } from '@encryption/src/crypto/vault-unlock';
import { prisma } from '@encryption/src/prisma/client';
import { vaultRoute } from '@encryption/src/server/routes/vault';
import { notifyVaultChanged } from '@encryption/src/server/vault-notify';
import {
  API_ERROR_CHALLENGE_NOT_FOUND,
  API_ERROR_VAULT_AUTH_BINDING_INVALID,
  API_ERROR_VAULT_ITEM_OUT_OF_DATE,
  API_ERROR_VAULT_KDF_PARAMS_INVALID,
  API_ERROR_VAULT_MANIFEST_INVALID,
  API_ERROR_VAULT_NOT_FOUND,
  API_ERROR_VAULT_PROOF_INVALID,
  API_ERROR_VAULT_REQUEST_SIGNATURE_INVALID,
} from '@encryption/src/shared/error-codes';

const mockTransaction = jest.fn();

// The server-push notifier is exercised as a spy here (does a successful write
// wake other devices?); the real SSE delivery is covered in the integration test.
jest.mock('@encryption/src/server/vault-notify', () => ({
  addVaultListener: jest.fn(),
  removeVaultListener: jest.fn(),
  notifyVaultChanged: jest.fn(),
}));

jest.mock('@encryption/src/prisma/client', () => ({
  prisma: {
    vaultKeyring: {
      findUnique: jest.fn(),
      findFirst: jest.fn(),
      findMany: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
      deleteMany: jest.fn(),
    },
    vaultMeta: { findUnique: jest.fn(), create: jest.fn(), update: jest.fn(), updateMany: jest.fn(), deleteMany: jest.fn() },
    vaultItem: { findUnique: jest.fn(), findMany: jest.fn(), upsert: jest.fn(), createMany: jest.fn(), deleteMany: jest.fn() },
    vaultChallenge: { create: jest.fn(), findUnique: jest.fn(), delete: jest.fn(), deleteMany: jest.fn() },
    vaultApproval: { create: jest.fn(), findUnique: jest.fn(), update: jest.fn(), delete: jest.fn(), deleteMany: jest.fn() },
    // Registration models, exercised by the atomic bootstrap that folds key
    // registration into the vault-create transaction.
    keyPossessionChallenge: { findUnique: jest.fn(), delete: jest.fn(), deleteMany: jest.fn() },
    encryptionKey: {
      findUnique: jest.fn(),
      findFirst: jest.fn(),
      aggregate: jest.fn(),
      count: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
    },
    identity: { findUnique: jest.fn(), findFirst: jest.fn(), aggregate: jest.fn(), create: jest.fn(), update: jest.fn(), updateMany: jest.fn() },
    $transaction: (...args: unknown[]) => mockTransaction(...args),
  },
}));

// Prisma's method types are complex generics that `jest.Mocked` doesn't unwrap
// cleanly, so view the mocked client as a plain map of jest mocks.
const mp = prisma as unknown as Record<string, Record<string, jest.Mock>>;
const USER_ID = 'user-1';
const FAST = { opsLimit: 1, memLimit: 8 * 1024 * 1024 };
const PHRASE = 'legal winner thank year wave sausage worth useful legal winner thank yellow';

type SigKeyPair = Awaited<ReturnType<typeof generateSignatureKeyPair>>;

// A manifest signed by `identity`, plus the identity public-key bytes the server
// verifies it against (versioned wire bytes, as stored). The server now checks
// manifestSig on every keyring/item write.
async function signedManifest(identity: SigKeyPair, revision = 4) {
  const m = buildManifest(revision, 1, []);

  return {
    manifest: JSON.stringify(m),
    manifest_sig: await signManifest(m, identity.secretKey),
    identityKeyBytes: base64ToUint8(exportPublicKeyAsBase64(identity.publicKey)),
  };
}

function buildApp() {
  const app = Fastify();
  app.decorate('verifyJWT', async (request: { userId?: string }) => {
    request.userId = USER_ID;
  });
  app.register(vaultRoute);

  return app;
}

// The identity the request-signature middleware accepts for USER_ID. Generated
// once; its wire public key is what `identity.findFirst` returns (see beforeEach).
let requestIdentity: SigKeyPair;

beforeAll(async () => {
  requestIdentity = await generateSignatureKeyPair();
});

// A valid identity X-Signature header for USER_ID bound to this method + path +
// body, as the real client produces it. `body` must be the EXACT serialized bytes
// the request sends (Fastify's inject serializes an object payload with
// JSON.stringify, so pass JSON.stringify(payload)). Passed to `inject` for
// COVERED routes.
async function sigHeaders(
  method: string,
  url: string,
  body = '',
  secretKey: Uint8Array = requestIdentity.secretKey
): Promise<Record<string, string>> {
  const token = await signRequestProof({
    method,
    path: url,
    body,
    userId: USER_ID,
    identitySecretKey: secretKey,
    nowSeconds: Math.floor(Date.now() / 1000),
  });

  return { [REQUEST_SIG_HEADER]: token };
}

beforeEach(() => {
  jest.clearAllMocks();
  // A transaction callback runs against the mocked prisma; an array resolves.
  mockTransaction.mockImplementation((arg: unknown) =>
    typeof arg === 'function' ? (arg as (tx: typeof prisma) => unknown)(prisma) : Promise.all(arg as unknown[])
  );
  // The middleware resolves the acceptable identity key from the active identity.
  mp.identity.findFirst.mockResolvedValue({ signaturePublicKey: Buffer.from(base64ToUint8(exportPublicKeyAsBase64(requestIdentity.publicKey))) });
});

describe('POST /api/vault/fetch (proof of possession gate)', () => {
  async function authKeys() {
    const kek = await deriveKek(PHRASE, USER_ID, FAST);
    return deriveVaultAuthKeyPair(kek);
  }

  it('releases the wrappedVrk only for a valid proof', async () => {
    const auth = await authKeys();
    const nonce = randomBytes(32);

    mp.vaultChallenge.findUnique.mockResolvedValue({ id: 'c1', userId: USER_ID, nonce, expiresAt: new Date(Date.now() + 60000) } as never);
    mp.vaultKeyring.findMany.mockResolvedValue([
      { id: 'v1', userId: USER_ID, wrappedVrk: 'WRAPPED', authPublicKey: auth.publicKey, disabledAt: null, createdAt: new Date(1) },
    ] as never);
    mp.vaultMeta.findUnique.mockResolvedValue({ accountRevision: 3, manifest: 'M', manifestSig: Buffer.from('S') } as never);
    mp.vaultItem.findMany.mockResolvedValue([] as never);
    mp.vaultChallenge.deleteMany.mockResolvedValue({ count: 1 } as never);

    const proof = uint8ToBase64(await signVaultChallenge(new Uint8Array(nonce), USER_ID, auth.secretKey));
    const res = await buildApp().inject({ method: 'POST', url: '/api/vault/fetch', payload: { challenge_id: 'c1', proof } });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ vault_id: 'v1', is_active: true, wrapped_vrk: 'WRAPPED', revision: 3 });
    expect(mp.vaultChallenge.deleteMany).toHaveBeenCalled(); // single-use
  });

  it('self-selects a dormant vault by its phrase among several keyrings', async () => {
    const active = await authKeys();
    const dormant = await deriveVaultAuthKeyPair(await deriveKek('the old superseded vault phrase words here now yes', USER_ID, FAST));
    const nonce = randomBytes(32);

    mp.vaultChallenge.findUnique.mockResolvedValue({ id: 'c1', userId: USER_ID, nonce, expiresAt: new Date(Date.now() + 60000) } as never);
    // The active vault comes first, but the proof was signed with the dormant
    // vault's phrase, so the walk must pick the dormant one.
    mp.vaultKeyring.findMany.mockResolvedValue([
      {
        id: 'v-active',
        userId: USER_ID,
        wrappedVrk: 'NEW',
        authPublicKey: active.publicKey,
        disabledAt: null,
        createdAt: new Date(2),
      },
      {
        id: 'v-old',
        userId: USER_ID,
        wrappedVrk: 'OLD',
        authPublicKey: dormant.publicKey,
        disabledAt: new Date(),
        createdAt: new Date(1),
      },
    ] as never);
    mp.vaultMeta.findUnique.mockResolvedValue({ accountRevision: 1, manifest: 'OM', manifestSig: Buffer.from('OS') } as never);
    mp.vaultItem.findMany.mockResolvedValue([] as never);
    mp.vaultChallenge.deleteMany.mockResolvedValue({ count: 1 } as never);

    const proof = uint8ToBase64(await signVaultChallenge(new Uint8Array(nonce), USER_ID, dormant.secretKey));
    const res = await buildApp().inject({ method: 'POST', url: '/api/vault/fetch', payload: { challenge_id: 'c1', proof } });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ vault_id: 'v-old', is_active: false, wrapped_vrk: 'OLD' });
    // The dormant vault's items were read (by its vaultId), not the active one's.
    expect(mp.vaultItem.findMany).toHaveBeenCalledWith({ where: { vaultId: 'v-old' } });
  });

  it('rejects a proof signed by the wrong phrase and never releases the vault', async () => {
    const auth = await authKeys();
    const wrong = await deriveVaultAuthKeyPair(await deriveKek('a different phrase for the wrong key here now', USER_ID, FAST));
    const nonce = randomBytes(32);

    mp.vaultChallenge.findUnique.mockResolvedValue({ id: 'c1', userId: USER_ID, nonce, expiresAt: new Date(Date.now() + 60000) } as never);
    mp.vaultKeyring.findMany.mockResolvedValue([{ id: 'v1', userId: USER_ID, wrappedVrk: 'WRAPPED', authPublicKey: auth.publicKey }] as never);

    const proof = uint8ToBase64(await signVaultChallenge(new Uint8Array(nonce), USER_ID, wrong.secretKey));
    const res = await buildApp().inject({ method: 'POST', url: '/api/vault/fetch', payload: { challenge_id: 'c1', proof } });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe(API_ERROR_VAULT_PROOF_INVALID);
    expect(mp.vaultItem.findMany).not.toHaveBeenCalled();
  });
});

describe('POST /api/vault/reactivate (bring a dormant vault back)', () => {
  async function keyFor(phrase: string) {
    return deriveVaultAuthKeyPair(await deriveKek(phrase, USER_ID, FAST));
  }

  it('reactivates a dormant vault: flips the directory and the keyrings', async () => {
    const activeKp = await keyFor(PHRASE);
    const targetKp = await keyFor('the older vault i want to bring back now please yes');
    const nonce = randomBytes(32);

    mp.vaultChallenge.findUnique.mockResolvedValue({ id: 'c1', userId: USER_ID, nonce, expiresAt: new Date(Date.now() + 60000) } as never);
    mp.vaultKeyring.findMany.mockResolvedValue([
      { id: 'v-active', userId: USER_ID, authPublicKey: activeKp.publicKey, identityId: 'id-active', disabledAt: null },
      {
        id: 'v-old',
        userId: USER_ID,
        wrappedVrk: 'OLD',
        authPublicKey: targetKp.publicKey,
        identityId: 'id-old',
        disabledAt: new Date(),
        createdAt: new Date(1),
      },
    ] as never);
    mp.vaultChallenge.deleteMany.mockResolvedValue({ count: 1 } as never);
    // previouslyActive (the vault being demoted) + the target identity's latest key.
    mp.vaultKeyring.findFirst.mockResolvedValue({ id: 'v-active', createdAt: new Date(2), disabledAt: null } as never);
    mp.encryptionKey.findFirst.mockResolvedValue({ id: 'k-old', identityId: 'id-old', version: 1 } as never);
    // The recovered vault's content, released so the client caches it post-switch.
    mp.vaultMeta.findUnique.mockResolvedValue({ accountRevision: 1, manifest: 'OM', manifestSig: Buffer.from('OS') } as never);
    mp.vaultItem.findMany.mockResolvedValue([] as never);

    const proof = uint8ToBase64(await signVaultChallenge(new Uint8Array(nonce), USER_ID, targetKp.secretKey));
    const res = await buildApp().inject({ method: 'POST', url: '/api/vault/reactivate', payload: { challenge_id: 'c1', proof } });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      reactivated: true,
      active_vault_id: 'v-old',
      disabled_vault_id: 'v-active',
      vault_id: 'v-old',
      wrapped_vrk: 'OLD',
    });
    // The recovered vault's content is released so the client can cache it.
    expect(mp.vaultItem.findMany).toHaveBeenCalledWith({ where: { vaultId: 'v-old' } });
    // The directory was re-pointed at the recovered vault's identity + key.
    expect(mp.encryptionKey.updateMany).toHaveBeenCalled();
    expect(mp.identity.update).toHaveBeenCalledWith({ where: { id: 'id-old' }, data: { disabledAt: null } });
    // The recovered keyring is promoted; the previously active ones are demoted.
    expect(mp.vaultKeyring.updateMany).toHaveBeenCalledWith({ where: { userId: USER_ID, disabledAt: null }, data: { disabledAt: expect.any(Date) } });
    expect(mp.vaultKeyring.update).toHaveBeenCalledWith({ where: { id: 'v-old' }, data: { disabledAt: null } });
  });

  it('is a no-op when the phrase already unlocks the active vault', async () => {
    const activeKp = await keyFor(PHRASE);
    const nonce = randomBytes(32);

    mp.vaultChallenge.findUnique.mockResolvedValue({ id: 'c1', userId: USER_ID, nonce, expiresAt: new Date(Date.now() + 60000) } as never);
    mp.vaultKeyring.findMany.mockResolvedValue([
      {
        id: 'v-active',
        userId: USER_ID,
        wrappedVrk: 'CUR',
        authPublicKey: activeKp.publicKey,
        identityId: 'id-active',
        disabledAt: null,
      },
    ] as never);
    mp.vaultChallenge.deleteMany.mockResolvedValue({ count: 1 } as never);
    mp.vaultMeta.findUnique.mockResolvedValue({ accountRevision: 4, manifest: 'M', manifestSig: Buffer.from('S') } as never);
    mp.vaultItem.findMany.mockResolvedValue([] as never);

    const proof = uint8ToBase64(await signVaultChallenge(new Uint8Array(nonce), USER_ID, activeKp.secretKey));
    const res = await buildApp().inject({ method: 'POST', url: '/api/vault/reactivate', payload: { challenge_id: 'c1', proof } });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ reactivated: false, active_vault_id: 'v-active', wrapped_vrk: 'CUR' });
    expect(mp.vaultKeyring.update).not.toHaveBeenCalled();
    expect(mp.encryptionKey.updateMany).not.toHaveBeenCalled();
  });

  it('rejects a wrong phrase without touching any vault', async () => {
    const activeKp = await keyFor(PHRASE);
    const wrong = await keyFor('a totally different phrase that matches nothing here now');
    const nonce = randomBytes(32);

    mp.vaultChallenge.findUnique.mockResolvedValue({ id: 'c1', userId: USER_ID, nonce, expiresAt: new Date(Date.now() + 60000) } as never);
    mp.vaultKeyring.findMany.mockResolvedValue([
      { id: 'v-active', userId: USER_ID, authPublicKey: activeKp.publicKey, identityId: 'id-active', disabledAt: null },
    ] as never);

    const proof = uint8ToBase64(await signVaultChallenge(new Uint8Array(nonce), USER_ID, wrong.secretKey));
    const res = await buildApp().inject({ method: 'POST', url: '/api/vault/reactivate', payload: { challenge_id: 'c1', proof } });

    expect(res.statusCode).toBe(401);
    expect(mp.vaultKeyring.update).not.toHaveBeenCalled();
    expect(mp.vaultKeyring.updateMany).not.toHaveBeenCalled();
  });
});

describe('PUT /api/vault/items/:itemId (optimistic concurrency)', () => {
  let identity: SigKeyPair;
  let sm: Awaited<ReturnType<typeof signedManifest>>;

  beforeAll(async () => {
    identity = await generateSignatureKeyPair();
    sm = await signedManifest(identity);
  });

  const body = (lastKnown: number | null) => ({
    item: { item_id: 'tofu:bob', type: 'tofu', ciphertext: 'CT', revision_date_millis: 9000 },
    last_known_revision_date_millis: lastKnown,
    manifest: sm.manifest,
    manifest_sig: sm.manifest_sig,
    revision: 4,
  });

  // Active vault + its identity, so the manifest-signature check passes.
  const activeVault = () => {
    mp.vaultKeyring.findFirst.mockResolvedValue({ id: 'v1', userId: USER_ID, identityId: 'id1', disabledAt: null } as never);
    mp.identity.findUnique.mockResolvedValue({ id: 'id1', signaturePublicKey: sm.identityKeyBytes } as never);
  };

  it('accepts a write when the client saw the current revision', async () => {
    activeVault();
    mp.vaultItem.findUnique.mockResolvedValue({ revisionDate: new Date(1000) } as never);
    // body revision is 4, so the CAS advances the row still sitting at 3: one match.
    mp.vaultMeta.updateMany.mockResolvedValue({ count: 1 } as never);
    mp.vaultItem.upsert.mockResolvedValue({} as never);

    const reqBody = body(1000);
    const res = await buildApp().inject({
      method: 'PUT',
      url: '/api/vault/items/tofu:bob',
      payload: reqBody,
      headers: await sigHeaders('PUT', '/api/vault/items/tofu:bob', JSON.stringify(reqBody)),
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ revision: 4 });
    // A successful write wakes the user's other devices (server-push).
    expect(notifyVaultChanged).toHaveBeenCalledWith(USER_ID, 4);
    // The CAS is filtered on the expected prior revision, not an unconditional write.
    expect(mp.vaultMeta.updateMany).toHaveBeenCalledWith(expect.objectContaining({ where: { vaultId: 'v1', accountRevision: 3 } }));
    // The write is scoped to the active vault, not the raw userId.
    expect(mp.vaultItem.upsert).toHaveBeenCalledWith(expect.objectContaining({ where: { vaultId_itemId: { vaultId: 'v1', itemId: 'tofu:bob' } } }));
  });

  it('rejects a write that is out of date with 409', async () => {
    activeVault();
    mp.vaultItem.findUnique.mockResolvedValue({ revisionDate: new Date(5000) } as never);

    const reqBody = body(1000);
    const res = await buildApp().inject({
      method: 'PUT',
      url: '/api/vault/items/tofu:bob',
      payload: reqBody,
      headers: await sigHeaders('PUT', '/api/vault/items/tofu:bob', JSON.stringify(reqBody)),
    });

    expect(res.statusCode).toBe(409);
    expect(res.json().code).toBe(API_ERROR_VAULT_ITEM_OUT_OF_DATE);
    expect(mp.vaultItem.upsert).not.toHaveBeenCalled();
  });

  it('rejects a write that does not advance the account revision by exactly one (409)', async () => {
    activeVault();
    // The item is current, but a concurrent write already moved the account to 4,
    // so this write (revision 4, expecting a base of 3) must lose and re-sync. The
    // conditional CAS matches no row still at revision 3, so no row is updated.
    mp.vaultItem.findUnique.mockResolvedValue({ revisionDate: new Date(1000) } as never);
    mp.vaultMeta.updateMany.mockResolvedValue({ count: 0 } as never);

    const reqBody = body(1000);
    const res = await buildApp().inject({
      method: 'PUT',
      url: '/api/vault/items/tofu:bob',
      payload: reqBody,
      headers: await sigHeaders('PUT', '/api/vault/items/tofu:bob', JSON.stringify(reqBody)),
    });

    expect(res.statusCode).toBe(409);
    expect(res.json().code).toBe(API_ERROR_VAULT_ITEM_OUT_OF_DATE);
    expect(mp.vaultItem.upsert).not.toHaveBeenCalled();
  });

  it('rejects a write whose signed manifest declares a different revision (400)', async () => {
    activeVault();
    // Body claims revision 5 but carries the revision-4 signed manifest.
    const reqBody = { ...body(1000), revision: 5 };
    const res = await buildApp().inject({
      method: 'PUT',
      url: '/api/vault/items/tofu:bob',
      payload: reqBody,
      headers: await sigHeaders('PUT', '/api/vault/items/tofu:bob', JSON.stringify(reqBody)),
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_VAULT_MANIFEST_INVALID);
    expect(mp.vaultItem.upsert).not.toHaveBeenCalled();
  });

  it('rejects a create the client thought was new but already exists', async () => {
    activeVault();
    mp.vaultItem.findUnique.mockResolvedValue({ revisionDate: new Date(1000) } as never);

    const reqBody = body(null);
    const res = await buildApp().inject({
      method: 'PUT',
      url: '/api/vault/items/tofu:bob',
      payload: reqBody,
      headers: await sigHeaders('PUT', '/api/vault/items/tofu:bob', JSON.stringify(reqBody)),
    });

    expect(res.statusCode).toBe(409);
  });

  it('404s when the user has no active vault', async () => {
    mp.vaultKeyring.findFirst.mockResolvedValue(null as never);

    const reqBody = body(1000);
    const res = await buildApp().inject({
      method: 'PUT',
      url: '/api/vault/items/tofu:bob',
      payload: reqBody,
      headers: await sigHeaders('PUT', '/api/vault/items/tofu:bob', JSON.stringify(reqBody)),
    });

    expect(res.statusCode).toBe(404);
    expect(mp.vaultItem.upsert).not.toHaveBeenCalled();
  });
});

describe('GET /api/vault/items (warm-sync pull)', () => {
  it('returns the sealed items + manifest + revision without the wrappedVrk', async () => {
    mp.vaultKeyring.findFirst.mockResolvedValue({ id: 'v1', userId: USER_ID, disabledAt: null } as never);
    mp.vaultMeta.findUnique.mockResolvedValue({ accountRevision: 5, manifest: 'M', manifestSig: Buffer.from('S') } as never);
    mp.vaultItem.findMany.mockResolvedValue([{ itemId: 'tofu:bob', type: 'tofu', ciphertext: 'CT', revisionDate: new Date(9000) }] as never);

    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/items', headers: await sigHeaders('GET', '/api/vault/items') });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toMatchObject({ revision: 5, manifest: 'M', manifest_sig: uint8ToBase64(Buffer.from('S')) });
    expect(body.items).toEqual([{ item_id: 'tofu:bob', type: 'tofu', ciphertext: 'CT', revision_date_millis: 9000 }]);
    // The passphrase-brute-forceable artifact is never in this JWT-only response.
    expect(body.wrapped_vrk).toBeUndefined();
    // Items are read scoped to the active vault's id.
    expect(mp.vaultItem.findMany).toHaveBeenCalledWith({ where: { vaultId: 'v1' } });
  });

  it('reports an empty vault (no active keyring) as revision 0 with no items', async () => {
    mp.vaultKeyring.findFirst.mockResolvedValue(null as never);

    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/items', headers: await sigHeaders('GET', '/api/vault/items') });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ revision: 0, manifest: null, manifest_sig: null, items: [] });
    expect(mp.vaultItem.findMany).not.toHaveBeenCalled();
  });
});

describe('identity request-signature middleware', () => {
  it('rejects a covered route with NO signature (401)', async () => {
    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/items' });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe(API_ERROR_VAULT_REQUEST_SIGNATURE_INVALID);
    expect(mp.vaultKeyring.findFirst).not.toHaveBeenCalled();
  });

  it('rejects a signature minted for a DIFFERENT path (401)', async () => {
    // A valid proof, but bound to /keyring — it must not authorize /items.
    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/items', headers: await sigHeaders('GET', '/api/vault/keyring') });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe(API_ERROR_VAULT_REQUEST_SIGNATURE_INVALID);
  });

  it('rejects when the account has no active identity to accept a signature from (401)', async () => {
    mp.identity.findFirst.mockResolvedValue(null as never);

    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/items', headers: await sigHeaders('GET', '/api/vault/items') });

    expect(res.statusCode).toBe(401);
  });

  it('rejects a tier-2 request whose signature subject differs from the JWT user (401)', async () => {
    // JWT authenticates USER_ID (verifyJWT mock), but the signature is minted for a
    // DIFFERENT user — a valid token for one account paired with another's signature.
    const token = await signRequestProof({
      method: 'GET',
      path: '/api/vault/approvals/pending',
      userId: 'someone-else',
      identitySecretKey: requestIdentity.secretKey,
      nowSeconds: Math.floor(Date.now() / 1000),
    });

    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/approvals/pending', headers: { [REQUEST_SIG_HEADER]: token } });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe(API_ERROR_VAULT_REQUEST_SIGNATURE_INVALID);
  });

  it('rejects a covered write whose BODY was swapped after signing (401)', async () => {
    // The signature is over one body; a different payload is sent. The middleware
    // rejects on the body-digest mismatch before the handler ever runs.
    const res = await buildApp().inject({
      method: 'PUT',
      url: '/api/vault/items/tofu:bob',
      payload: { swapped: 'evil' },
      headers: await sigHeaders('PUT', '/api/vault/items/tofu:bob', JSON.stringify({ swapped: 'good' })),
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe(API_ERROR_VAULT_REQUEST_SIGNATURE_INVALID);
    expect(mp.vaultItem.upsert).not.toHaveBeenCalled();
  });
});

describe('identity migration: a continuity-linked predecessor may still authenticate', () => {
  // Set up an active gen-2 identity cross-signed by a gen-1 predecessor, and mock
  // the DB rows. Returns the predecessor keypair so the test can sign as a device
  // still on gen 1. `mp.identity.findFirst` returns the active row (walk start);
  // `mp.identity.findUnique` returns the predecessor.
  async function chain(opts: { supersededMsAgo?: number; prevDisabled?: boolean; badCrossSig?: boolean } = {}) {
    const prev = await generateSignatureKeyPair();
    const active = await generateSignatureKeyPair();
    const activeWire = base64ToUint8(exportPublicKeyAsBase64(active.publicKey));
    const prevWire = base64ToUint8(exportPublicKeyAsBase64(prev.publicKey));

    const payload = encodeIdentityContinuityPayload({ userId: USER_ID, generation: 2, algo: 'ed25519', signaturePublicKeyWire: activeWire });
    const crossSig = opts.badCrossSig ? new Uint8Array(64) : await signDetached(payload, prev.secretKey);

    // The active (successor) row's createdAt IS when the predecessor was superseded.
    mp.identity.findFirst.mockResolvedValue({
      signaturePublicKey: Buffer.from(activeWire),
      userId: USER_ID,
      generation: 2,
      algo: 'ed25519',
      disabledAt: null,
      createdAt: new Date(Date.now() - (opts.supersededMsAgo ?? 24 * 60 * 60 * 1000)),
      previousIdentityId: 'prev-id',
      continuitySignature: Buffer.from(crossSig),
    } as never);
    mp.identity.findUnique.mockResolvedValue({
      id: 'prev-id',
      signaturePublicKey: Buffer.from(prevWire),
      userId: USER_ID,
      generation: 1,
      algo: 'ed25519',
      disabledAt: opts.prevDisabled ? new Date() : null,
      previousIdentityId: null,
      continuitySignature: null,
    } as never);

    return prev;
  }

  it('accepts a request signed by an in-window, cross-signed predecessor', async () => {
    const prev = await chain({ supersededMsAgo: 24 * 60 * 60 * 1000 }); // 1 day ago
    mp.vaultKeyring.findFirst.mockResolvedValue(null as never); // empty vault → 200 once auth passes

    const res = await buildApp().inject({
      method: 'GET',
      url: '/api/vault/items',
      headers: await sigHeaders('GET', '/api/vault/items', '', prev.secretKey),
    });

    expect(res.statusCode).toBe(200);
  });

  it('rejects a predecessor superseded longer than the grace window ago', async () => {
    const prev = await chain({ supersededMsAgo: 400 * 24 * 60 * 60 * 1000 }); // ~400 days

    const res = await buildApp().inject({
      method: 'GET',
      url: '/api/vault/items',
      headers: await sigHeaders('GET', '/api/vault/items', '', prev.secretKey),
    });

    expect(res.statusCode).toBe(401);
  });

  it('rejects a predecessor that has been disabled (revoked)', async () => {
    const prev = await chain({ prevDisabled: true });

    const res = await buildApp().inject({
      method: 'GET',
      url: '/api/vault/items',
      headers: await sigHeaders('GET', '/api/vault/items', '', prev.secretKey),
    });

    expect(res.statusCode).toBe(401);
  });

  it('rejects a predecessor whose continuity cross-signature does not verify', async () => {
    const prev = await chain({ badCrossSig: true });

    const res = await buildApp().inject({
      method: 'GET',
      url: '/api/vault/items',
      headers: await sigHeaders('GET', '/api/vault/items', '', prev.secretKey),
    });

    expect(res.statusCode).toBe(401);
  });
});

describe('GET /api/vault/meta (KDF variants for restore)', () => {
  it('returns the DISTINCT KDF variants across all keyrings (dormant included), cheapest first', async () => {
    // Two vaults on the current params + one older vault on weaker params, plus a
    // dormant duplicate. Restore must be able to try each distinct set.
    mp.vaultKeyring.findMany.mockResolvedValue([
      { kdfOps: 3, kdfMem: 64 * 1024 * 1024 },
      { kdfOps: 5, kdfMem: 128 * 1024 * 1024 },
      { kdfOps: 3, kdfMem: 64 * 1024 * 1024 }, // duplicate → collapsed
    ] as never);

    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/meta' });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      kdf_variants: [
        { kdf_ops: 3, kdf_mem: 64 * 1024 * 1024 },
        { kdf_ops: 5, kdf_mem: 128 * 1024 * 1024 },
      ],
    });
    // Any keyring status counts (dormant vaults are restorable).
    expect(mp.vaultKeyring.findMany).toHaveBeenCalledWith({ where: { userId: USER_ID }, select: { kdfOps: true, kdfMem: true } });
  });

  it('404s only when the user has NO keyring at all', async () => {
    mp.vaultKeyring.findMany.mockResolvedValue([] as never);

    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/meta' });

    expect(res.statusCode).toBe(404);
    expect(res.json().code).toBe(API_ERROR_VAULT_NOT_FOUND);
  });
});

describe('POST /api/vault (atomic onboarding)', () => {
  const bootstrapBody = {
    registration: { challenge_id: '00000000-0000-0000-0000-000000000000', response: 'AA', challenge_signature: 'BB' },
    // KDF params must be the server-pinned standard (DEFAULT_KDF_PARAMS): ops 3, mem 64 MiB.
    keyring: { wrapped_vrk: 'W', auth_public_key: 'A', auth_pub_sig: 'S', kdf_ops: 3, kdf_mem: 64 * 1024 * 1024, lang: 'en' },
    items: [{ item_id: 'active', type: 'active', ciphertext: 'CT', revision_date_millis: 1 }],
    manifest: 'M',
    manifest_sig: 'MS',
  };

  // A valid dual-key proof + the registration mocks needed to drive the
  // onboarding transaction to success. The HMAC check is a plain memcmp, so any
  // matching bytes pass; a real signature key signs the challenge id.
  async function successfulOnboardingBody() {
    const signature = await generateSignatureKeyPair();
    const signaturePublicKey = exportPublicKeyAsBase64(signature.publicKey);
    const challengeId = '11111111-1111-4111-8111-111111111111';
    const hmac = new Uint8Array(32).fill(7);
    const challengeSig = uint8ToBase64(await signDetached(encodePopChallengeMessage(challengeId), signature.secretKey));

    const challengeRow = {
      id: challengeId,
      userId: USER_ID,
      encryptionPublicKey: Buffer.from('enc'),
      signaturePublicKey: base64ToUint8(signaturePublicKey),
      keyBindingSignature: Buffer.from('bind'),
      version: 1,
      signedCreatedAt: new Date(1),
      expectedHmac: hmac,
      expiresAt: new Date(Date.now() + 60000),
    };

    mp.keyPossessionChallenge.findUnique.mockResolvedValue(challengeRow as never);
    mp.encryptionKey.findUnique.mockResolvedValue(null as never); // brand-new encryption key
    mp.identity.findUnique
      .mockResolvedValueOnce(null as never)
      .mockResolvedValue({ id: 'identity-new', userId: USER_ID, signaturePublicKey: base64ToUint8(signaturePublicKey), disabledAt: null } as never);
    mp.encryptionKey.count.mockResolvedValue(0 as never); // under the rate limit
    mp.encryptionKey.aggregate.mockResolvedValue({ _max: { version: null } } as never); // expected version = 1
    mp.identity.aggregate.mockResolvedValue({ _max: { generation: null } } as never);
    mp.identity.create.mockResolvedValue({ id: 'identity-new' } as never);
    mp.encryptionKey.create.mockResolvedValue({
      id: 'key-new',
      userId: USER_ID,
      encryptionPublicKey: Buffer.from('enc'),
      keyBindingSignature: Buffer.from('bind'),
      version: 1,
      createdAt: new Date(1),
      identity: { signaturePublicKey: base64ToUint8(signaturePublicKey) },
    } as never);
    mp.vaultKeyring.create.mockResolvedValue({ id: 'vault-new', userId: USER_ID } as never);

    // The keyring's auth verifier must be signed by the identity (authPubSig),
    // which the server now enforces. Build a real binding: the identity secret
    // signs the domain-separated binding over the auth public key.
    const authKeyPair = await generateSignatureKeyPair();
    const authPubSig = await signAuthPublicKeyBinding(authKeyPair.publicKey, signature.secretKey);
    // The manifest must be signed by the same identity (server now verifies it).
    const sm = await signedManifest(signature, 1);

    return {
      ...bootstrapBody,
      manifest: sm.manifest,
      manifest_sig: sm.manifest_sig,
      keyring: { ...bootstrapBody.keyring, auth_public_key: uint8ToBase64(authKeyPair.publicKey), auth_pub_sig: uint8ToBase64(authPubSig) },
      registration: { challenge_id: challengeId, response: uint8ToBase64(hmac), challenge_signature: challengeSig },
    };
  }

  it('rejects (400, no vault writes) when the keyring KDF params are not the pinned standard', async () => {
    // A weak / non-standard KDF cost: pinning rejects it (checked before the proof)
    // so no brute-forceable or param-mismatched vault is ever stored. Uses the
    // static body so no proof/identity mocks are set up (and left dangling).
    const tampered = { ...bootstrapBody, keyring: { ...bootstrapBody.keyring, kdf_ops: 1 } };

    const res = await buildApp().inject({ method: 'POST', url: '/api/vault', payload: tampered });

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_VAULT_KDF_PARAMS_INVALID);
    expect(mp.vaultKeyring.create).not.toHaveBeenCalled();
    expect(mp.encryptionKey.create).not.toHaveBeenCalled();
  });

  it('refuses to onboard (no vault writes) when the registration proof is invalid', async () => {
    // No challenge on record → proof of possession fails before any write.
    mp.keyPossessionChallenge.findUnique.mockResolvedValue(null as never);

    const res = await buildApp().inject({ method: 'POST', url: '/api/vault', payload: bootstrapBody });

    expect(res.statusCode).toBe(404);
    expect(res.json().code).toBe(API_ERROR_CHALLENGE_NOT_FOUND);
    // The whole point of the fold: keys OR vault, never a half-written state.
    expect(mp.vaultKeyring.create).not.toHaveBeenCalled();
    expect(mp.vaultItem.createMany).not.toHaveBeenCalled();
    expect(mp.encryptionKey.create).not.toHaveBeenCalled();
  });

  it('supersedes the current vault (never deletes it) and creates a new active one', async () => {
    const body = await successfulOnboardingBody();

    const res = await buildApp().inject({ method: 'POST', url: '/api/vault', payload: body });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ revision: 1 });
    // The previous active vault is marked dormant, not deleted.
    expect(mp.vaultKeyring.updateMany).toHaveBeenCalledWith({ where: { userId: USER_ID, disabledAt: null }, data: { disabledAt: expect.any(Date) } });
    expect(mp.vaultKeyring.deleteMany).not.toHaveBeenCalled();
    expect(mp.vaultItem.deleteMany).not.toHaveBeenCalled();
    expect(mp.vaultMeta.deleteMany).not.toHaveBeenCalled();
    // The fresh vault's items and meta are written under the new vault id.
    expect(mp.vaultItem.createMany).toHaveBeenCalledWith({
      data: [expect.objectContaining({ vaultId: 'vault-new', itemId: 'active' })],
    });
    expect(mp.vaultMeta.create).toHaveBeenCalledWith({ data: expect.objectContaining({ vaultId: 'vault-new', accountRevision: 1 }) });
  });

  it('rejects (400, no vault writes) when authPubSig is not signed by the identity', async () => {
    const body = await successfulOnboardingBody();
    // Passes PoP, but the auth verifier is NOT bound to the identity: a wrong
    // signature over the auth public key (as a token-thief substituting a rogue
    // verifier would produce).
    const rogue = await generateSignatureKeyPair();
    const authPub = base64ToUint8(body.keyring.auth_public_key);
    body.keyring.auth_pub_sig = uint8ToBase64(await signAuthPublicKeyBinding(authPub, rogue.secretKey));

    const res = await buildApp().inject({ method: 'POST', url: '/api/vault', payload: body });

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_VAULT_AUTH_BINDING_INVALID);
    expect(mp.vaultKeyring.create).not.toHaveBeenCalled();
  });

  it('rejects (400, no vault writes) when the manifest is not signed by the identity', async () => {
    const body = await successfulOnboardingBody();
    // Passes PoP + auth binding, but the manifest is signed by a DIFFERENT key.
    const rogue = await generateSignatureKeyPair();
    const rogueManifest = await signedManifest(rogue, 1);
    body.manifest_sig = rogueManifest.manifest_sig;

    const res = await buildApp().inject({ method: 'POST', url: '/api/vault', payload: body });

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_VAULT_MANIFEST_INVALID);
    expect(mp.vaultKeyring.create).not.toHaveBeenCalled();
  });
});
