import Fastify from 'fastify';
import { randomBytes } from 'node:crypto';

import { uint8ToBase64 } from '@encryption/src/crypto';
import { sha256, signEmergencyEscrow } from '@encryption/src/crypto/emergency-escrow';
import { base64ToUint8, exportPublicKeyAsBase64 } from '@encryption/src/crypto/encryption-backup';
import { encodeIdentityContinuityPayload, encodePopChallengeMessage } from '@encryption/src/crypto/key-registration';
import { REQUEST_SIG_HEADER, signRequestProof } from '@encryption/src/crypto/request-proof';
import { generateSignatureKeyPair, signDetached } from '@encryption/src/crypto/signature';
import { buildManifest, signManifest } from '@encryption/src/crypto/vault-manifest';
import { deriveKek, deriveVaultAuthKeyPair, signAuthPublicKeyBinding, signVaultChallenge } from '@encryption/src/crypto/vault-unlock';
import { testPrisma, useTestDatabase } from '@encryption/src/prisma/testing';
import { vaultRoute } from '@encryption/src/server/routes/vault';
import { notifyVaultChanged } from '@encryption/src/server/vault-notify';
import {
  API_ERROR_CHALLENGE_NOT_FOUND,
  API_ERROR_EMERGENCY_ESCROW_INVALID,
  API_ERROR_EMERGENCY_REARM_REQUIRED,
  API_ERROR_VAULT_AUTH_BINDING_INVALID,
  API_ERROR_VAULT_ITEM_OUT_OF_DATE,
  API_ERROR_VAULT_KDF_PARAMS_INVALID,
  API_ERROR_VAULT_MANIFEST_INVALID,
  API_ERROR_VAULT_NOT_FOUND,
  API_ERROR_VAULT_PROOF_INVALID,
  API_ERROR_VAULT_REQUEST_SIGNATURE_INVALID,
} from '@encryption/src/shared/error-codes';

// The keyring rewrite fires recovery notifications after a burn + re-arm; the
// shared manual mock (src/server/email/__mocks__/emergency.ts) makes them inert.
jest.mock('@encryption/src/server/email/emergency');

// The server-push notifier is exercised as a spy here (does a successful write
// wake other devices?); the real SSE delivery is covered in the integration test.
jest.mock('@encryption/src/server/vault-notify', () => ({
  addVaultListener: jest.fn(),
  removeVaultListener: jest.fn(),
  notifyVaultChanged: jest.fn(),
}));

jest.mock('@encryption/src/prisma/client', () => ({ prisma: jest.requireActual('@encryption/src/prisma/testing').testPrisma }));

useTestDatabase();

// Fixed so the value can be baked into request proofs and KDF derivations before
// any row exists; the user row is (re)created with this id before every test.
const USER_ID = 'd0d0d0d0-0000-4000-8000-000000000001';
const FAST = { opsLimit: 1, memLimit: 8 * 1024 * 1024 };
const PHRASE = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const KDF = { ops: 3, mem: 64 * 1024 * 1024 }; // the server-pinned standard

type SigKeyPair = Awaited<ReturnType<typeof generateSignatureKeyPair>>;
type SeededItem = { itemId: string; type: 'tofu' | 'active'; ciphertext: string; revisionDateMillis: number };

function wireKey(pair: SigKeyPair): Uint8Array {
  return base64ToUint8(exportPublicKeyAsBase64(pair.publicKey));
}

// A manifest signed by `identity`, plus the identity public-key bytes the server
// verifies it against (versioned wire bytes, as stored). The server now checks
// manifestSig on every keyring/item write.
async function signedManifest(identity: SigKeyPair, revision = 4) {
  const m = buildManifest(revision, 1, []);

  return {
    manifest: JSON.stringify(m),
    manifest_sig: await signManifest(m, identity.secretKey),
    identityKeyBytes: wireKey(identity),
  };
}

async function seedIdentity(
  pair: SigKeyPair,
  options: { generation?: number; disabledAt?: Date | null; createdAt?: Date; previousIdentityId?: string; continuitySignature?: Uint8Array } = {}
) {
  return testPrisma.identity.create({
    data: {
      userId: USER_ID,
      generation: options.generation ?? 1,
      signaturePublicKey: Buffer.from(wireKey(pair)),
      disabledAt: options.disabledAt ?? null,
      createdAt: options.createdAt,
      previousIdentityId: options.previousIdentityId ?? null,
      continuitySignature: options.continuitySignature ? Buffer.from(options.continuitySignature) : null,
    },
  });
}

async function seedEncryptionKey(options: { identityId: string; version: number; disabledAt?: Date | null }) {
  return testPrisma.encryptionKey.create({
    data: {
      userId: USER_ID,
      identityId: options.identityId,
      encryptionPublicKey: Buffer.from(`enc-key-${options.version}`),
      keyBindingSignature: Buffer.from('binding'),
      version: options.version,
      disabledAt: options.disabledAt ?? null,
    },
  });
}

// One vault: its keyring, its ONE primary credential (the unlock material lives
// there, not on the keyring), plus (optionally) its meta row and its sealed items.
async function seedVault(options: {
  identityId: string;
  authPublicKey?: Uint8Array;
  wrappedVrk?: string;
  disabledAt?: Date | null;
  createdAt?: Date;
  kdfOps?: number;
  kdfMem?: number;
  revision?: number;
  manifest?: string;
  manifestSig?: string;
  items?: SeededItem[];
}) {
  const keyring = await testPrisma.vaultKeyring.create({
    data: {
      userId: USER_ID,
      identityId: options.identityId,
      disabledAt: options.disabledAt ?? null,
      createdAt: options.createdAt,
      credentials: {
        create: {
          type: 'primary',
          wrappedVrk: options.wrappedVrk ?? 'WRAPPED',
          authPublicKey: Buffer.from(options.authPublicKey ?? new Uint8Array(32)),
          authPubSig: Buffer.from(new Uint8Array(64)),
          kdfOps: options.kdfOps ?? KDF.ops,
          kdfMem: options.kdfMem ?? KDF.mem,
          lang: 'english',
        },
      },
    },
  });

  if (options.revision !== undefined) {
    await testPrisma.vaultMeta.create({
      data: {
        vaultId: keyring.id,
        accountRevision: options.revision,
        manifest: options.manifest ?? 'M',
        manifestSig: Buffer.from(options.manifestSig ?? 'S'),
      },
    });
  }

  for (const item of options.items ?? []) {
    await testPrisma.vaultItem.create({
      data: {
        vaultId: keyring.id,
        itemId: item.itemId,
        type: item.type,
        ciphertext: item.ciphertext,
        revisionDate: new Date(item.revisionDateMillis),
      },
    });
  }

  return keyring;
}

const GRANTEE_ID = '66666666-6666-4666-8666-666666666666';

// A trusted-contact relationship on `vaultId`: the dormant emergency credential
// (a second keyslot on the same vault) plus the EmergencyAccess row owning it.
async function seedEmergencyAccess(options: {
  vaultId: string;
  authPublicKey?: Uint8Array;
  wrappedVrk?: string;
  kdfOps?: number;
  kdfMem?: number;
  status?: 'confirmed' | 'recoveryRequested' | 'recoveryApproved';
  waitTimeDays?: number;
  recoveryRequestedAt?: Date | null;
}) {
  await testPrisma.user.upsert({ where: { id: GRANTEE_ID }, create: { id: GRANTEE_ID, email: 'contact@example.org' }, update: {} });
  // The contact's pinned identity (its key is fill(9), matching the re-arm test's wire).
  const granteeIdentity = await testPrisma.identity.upsert({
    where: { signaturePublicKey: Buffer.from(new Uint8Array(33).fill(9)) },
    create: { userId: GRANTEE_ID, generation: 1, signaturePublicKey: Buffer.from(new Uint8Array(33).fill(9)) },
    update: {},
  });

  const credential = await testPrisma.vaultCredential.create({
    data: {
      vaultId: options.vaultId,
      type: 'emergency',
      wrappedVrk: options.wrappedVrk ?? 'EMERGENCY',
      authPublicKey: Buffer.from(options.authPublicKey ?? new Uint8Array(32).fill(1)),
      authPubSig: Buffer.from(new Uint8Array(64)),
      kdfOps: options.kdfOps ?? KDF.ops,
      kdfMem: options.kdfMem ?? KDF.mem,
      lang: 'english',
    },
  });

  const access = await testPrisma.emergencyAccess.create({
    data: {
      grantorUserId: USER_ID,
      granteeUserId: GRANTEE_ID,
      status: options.status ?? 'recoveryApproved',
      waitTimeDays: options.waitTimeDays ?? 15,
      credentialId: credential.id,
      wrappedPhraseForGrantee: 'CAPSULE',
      granteeIdentityId: granteeIdentity.id,
      granteeKeyVersion: 1,
      escrowSignature: Buffer.from(new Uint8Array(64)),
      escrowCreatedAt: new Date(1),
      recoveryRequestedAt: options.recoveryRequestedAt ?? null,
    },
  });

  return { credential, access };
}

async function primaryCredentialOf(vaultId: string) {
  return testPrisma.vaultCredential.findFirstOrThrow({ where: { vaultId, type: 'primary' } });
}

async function seedChallenge(nonce: Uint8Array, expiresAt = new Date(Date.now() + 60000)) {
  return testPrisma.vaultChallenge.create({ data: { userId: USER_ID, nonce: new Uint8Array(nonce), expiresAt } });
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
// once; its wire public key is what `seedRequestIdentity()` stores as the user's
// active identity.
let requestIdentity: SigKeyPair;

beforeAll(async () => {
  requestIdentity = await generateSignatureKeyPair();
});

beforeEach(async () => {
  jest.clearAllMocks();
  await testPrisma.user.create({ data: { id: USER_ID, email: 'vault@example.org' } });
});

async function seedRequestIdentity() {
  return seedIdentity(requestIdentity);
}

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

describe('POST /api/vault/fetch (proof of possession gate)', () => {
  async function authKeys() {
    const kek = await deriveKek(PHRASE, USER_ID, FAST);
    return deriveVaultAuthKeyPair(kek);
  }

  it('releases the wrappedVrk only for a valid proof', async () => {
    const auth = await authKeys();
    const identity = await seedRequestIdentity();
    const vault = await seedVault({ identityId: identity.id, authPublicKey: auth.publicKey, wrappedVrk: 'WRAPPED', revision: 3 });
    const nonce = randomBytes(32);
    const challenge = await seedChallenge(nonce);

    const proof = uint8ToBase64(await signVaultChallenge(new Uint8Array(nonce), USER_ID, auth.secretKey));
    const res = await buildApp().inject({ method: 'POST', url: '/api/vault/fetch', payload: { challenge_id: challenge.id, proof } });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ vault_id: vault.id, is_active: true, wrapped_vrk: 'WRAPPED', revision: 3 });
    // Single-use: the challenge row is gone once it has done its job.
    expect(await testPrisma.vaultChallenge.count()).toBe(0);
  });

  it('self-selects a dormant vault by its phrase among several keyrings', async () => {
    const active = await authKeys();
    const dormant = await deriveVaultAuthKeyPair(await deriveKek('the old superseded vault phrase words here now yes', USER_ID, FAST));
    const identity = await seedRequestIdentity();

    // The active vault holds its own content, but the proof is signed with the
    // dormant vault's phrase, so the walk must pick (and release) the dormant one.
    await seedVault({
      identityId: identity.id,
      authPublicKey: active.publicKey,
      wrappedVrk: 'NEW',
      createdAt: new Date(2),
      revision: 4,
      items: [{ itemId: 'tofu:new', type: 'tofu', ciphertext: 'NEWCT', revisionDateMillis: 2000 }],
    });
    const old = await seedVault({
      identityId: identity.id,
      authPublicKey: dormant.publicKey,
      wrappedVrk: 'OLD',
      disabledAt: new Date(),
      createdAt: new Date(1),
      revision: 1,
      manifest: 'OM',
      manifestSig: 'OS',
      items: [{ itemId: 'tofu:old', type: 'tofu', ciphertext: 'OLDCT', revisionDateMillis: 1000 }],
    });

    const nonce = randomBytes(32);
    const challenge = await seedChallenge(nonce);

    const proof = uint8ToBase64(await signVaultChallenge(new Uint8Array(nonce), USER_ID, dormant.secretKey));
    const res = await buildApp().inject({ method: 'POST', url: '/api/vault/fetch', payload: { challenge_id: challenge.id, proof } });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ vault_id: old.id, is_active: false, wrapped_vrk: 'OLD', revision: 1, manifest: 'OM' });
    // The dormant vault's items were read, not the active one's.
    expect(res.json().items).toEqual([{ item_id: 'tofu:old', type: 'tofu', ciphertext: 'OLDCT', revision_date_millis: 1000 }]);
  });

  it('rejects a proof signed by the wrong phrase and never releases the vault', async () => {
    const auth = await authKeys();
    const wrong = await deriveVaultAuthKeyPair(await deriveKek('a different phrase for the wrong key here now', USER_ID, FAST));
    const identity = await seedRequestIdentity();

    await seedVault({
      identityId: identity.id,
      authPublicKey: auth.publicKey,
      wrappedVrk: 'WRAPPED',
      revision: 1,
      items: [{ itemId: 'tofu:bob', type: 'tofu', ciphertext: 'CT', revisionDateMillis: 1000 }],
    });

    const nonce = randomBytes(32);
    const challenge = await seedChallenge(nonce);

    const proof = uint8ToBase64(await signVaultChallenge(new Uint8Array(nonce), USER_ID, wrong.secretKey));
    const res = await buildApp().inject({ method: 'POST', url: '/api/vault/fetch', payload: { challenge_id: challenge.id, proof } });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe(API_ERROR_VAULT_PROOF_INVALID);
    // Nothing of the vault leaked: no wrapped VRK, no items.
    expect(res.json().wrapped_vrk).toBeUndefined();
    expect(res.json().items).toBeUndefined();
  });

  it('unlocks an emergency credential only once the recovery is granted', async () => {
    const owner = await authKeys();
    const contact = await deriveVaultAuthKeyPair(await deriveKek('the emergency phrase held by the trusted contact now', USER_ID, FAST));
    const identity = await seedRequestIdentity();
    const vault = await seedVault({ identityId: identity.id, authPublicKey: owner.publicKey, wrappedVrk: 'OWNER', revision: 3 });
    const { access } = await seedEmergencyAccess({
      vaultId: vault.id,
      authPublicKey: contact.publicKey,
      wrappedVrk: 'EMERGENCY',
      status: 'confirmed',
    });

    const nonce = randomBytes(32);
    const proof = uint8ToBase64(await signVaultChallenge(new Uint8Array(nonce), USER_ID, contact.secretKey));

    // Dormant relationship: the emergency credential is not even a candidate, so
    // the contact's phrase looks like a wrong phrase.
    const before = await buildApp().inject({
      method: 'POST',
      url: '/api/vault/fetch',
      payload: { challenge_id: (await seedChallenge(nonce)).id, proof },
    });

    expect(before.statusCode).toBe(401);
    expect(before.json().code).toBe(API_ERROR_VAULT_PROOF_INVALID);

    // Once the wait period has elapsed the same phrase opens the SAME vault
    // through its own keyslot, flagged as emergency so the client burns it.
    await testPrisma.emergencyAccess.update({ where: { id: access.id }, data: { status: 'recoveryApproved' } });

    const after = await buildApp().inject({
      method: 'POST',
      url: '/api/vault/fetch',
      payload: { challenge_id: (await seedChallenge(nonce)).id, proof },
    });

    expect(after.statusCode).toBe(200);
    expect(after.json()).toMatchObject({ vault_id: vault.id, is_active: true, wrapped_vrk: 'EMERGENCY', credential_type: 'emergency', revision: 3 });
  });
});

describe('POST /api/vault/reactivate (bring a dormant vault back)', () => {
  async function keyFor(phrase: string) {
    return deriveVaultAuthKeyPair(await deriveKek(phrase, USER_ID, FAST));
  }

  it('reactivates a dormant vault: flips the directory and the keyrings', async () => {
    const activeKp = await keyFor(PHRASE);
    const targetKp = await keyFor('the older vault i want to bring back now please yes');

    // The state after a "start over": an older (dormant) identity + vault, and the
    // current active pair alongside it.
    const oldIdentity = await seedIdentity(await generateSignatureKeyPair(), { generation: 1, disabledAt: new Date() });
    const activeIdentity = await seedIdentity(requestIdentity, { generation: 2 });
    const oldKey = await seedEncryptionKey({ identityId: oldIdentity.id, version: 1, disabledAt: new Date() });
    const activeKey = await seedEncryptionKey({ identityId: activeIdentity.id, version: 2 });

    const activeVault = await seedVault({ identityId: activeIdentity.id, authPublicKey: activeKp.publicKey, createdAt: new Date(2), revision: 4 });
    const oldVault = await seedVault({
      identityId: oldIdentity.id,
      authPublicKey: targetKp.publicKey,
      wrappedVrk: 'OLD',
      disabledAt: new Date(),
      createdAt: new Date(1),
      revision: 1,
      manifest: 'OM',
      items: [{ itemId: 'tofu:old', type: 'tofu', ciphertext: 'OLDCT', revisionDateMillis: 1000 }],
    });

    const nonce = randomBytes(32);
    const challenge = await seedChallenge(nonce);

    const proof = uint8ToBase64(await signVaultChallenge(new Uint8Array(nonce), USER_ID, targetKp.secretKey));
    const res = await buildApp().inject({ method: 'POST', url: '/api/vault/reactivate', payload: { challenge_id: challenge.id, proof } });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      reactivated: true,
      active_vault_id: oldVault.id,
      disabled_vault_id: activeVault.id,
      vault_id: oldVault.id,
      wrapped_vrk: 'OLD',
    });
    // The recovered vault's content is released so the client can cache it.
    expect(res.json().items).toEqual([{ item_id: 'tofu:old', type: 'tofu', ciphertext: 'OLDCT', revision_date_millis: 1000 }]);
    // The directory was re-pointed at the recovered vault's identity + key.
    expect((await testPrisma.identity.findUniqueOrThrow({ where: { id: oldIdentity.id } })).disabledAt).toBeNull();
    expect((await testPrisma.identity.findUniqueOrThrow({ where: { id: activeIdentity.id } })).disabledAt).not.toBeNull();
    expect((await testPrisma.encryptionKey.findUniqueOrThrow({ where: { id: oldKey.id } })).disabledAt).toBeNull();
    expect((await testPrisma.encryptionKey.findUniqueOrThrow({ where: { id: activeKey.id } })).disabledAt).not.toBeNull();
    // The recovered keyring is promoted; the previously active one is demoted.
    expect((await testPrisma.vaultKeyring.findUniqueOrThrow({ where: { id: oldVault.id } })).disabledAt).toBeNull();
    expect((await testPrisma.vaultKeyring.findUniqueOrThrow({ where: { id: activeVault.id } })).disabledAt).not.toBeNull();
  });

  it('is a no-op when the phrase already unlocks the active vault', async () => {
    const activeKp = await keyFor(PHRASE);
    const identity = await seedRequestIdentity();
    const activeVault = await seedVault({ identityId: identity.id, authPublicKey: activeKp.publicKey, wrappedVrk: 'CUR', revision: 4 });
    const encryptionKey = await seedEncryptionKey({ identityId: identity.id, version: 1 });

    const nonce = randomBytes(32);
    const challenge = await seedChallenge(nonce);

    const proof = uint8ToBase64(await signVaultChallenge(new Uint8Array(nonce), USER_ID, activeKp.secretKey));
    const res = await buildApp().inject({ method: 'POST', url: '/api/vault/reactivate', payload: { challenge_id: challenge.id, proof } });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ reactivated: false, active_vault_id: activeVault.id, wrapped_vrk: 'CUR' });
    // Nothing was flipped: the vault and the directory rows are untouched.
    const keyring = await testPrisma.vaultKeyring.findUniqueOrThrow({ where: { id: activeVault.id } });
    expect(keyring.disabledAt).toBeNull();
    expect(keyring.updatedAt).toEqual(activeVault.updatedAt);
    expect((await testPrisma.encryptionKey.findUniqueOrThrow({ where: { id: encryptionKey.id } })).updatedAt).toEqual(encryptionKey.updatedAt);
  });

  it('rejects a wrong phrase without touching any vault', async () => {
    const activeKp = await keyFor(PHRASE);
    const wrong = await keyFor('a totally different phrase that matches nothing here now');
    const identity = await seedRequestIdentity();
    const activeVault = await seedVault({ identityId: identity.id, authPublicKey: activeKp.publicKey, revision: 4 });
    const dormantVault = await seedVault({ identityId: identity.id, disabledAt: new Date(), revision: 1 });

    const nonce = randomBytes(32);
    const challenge = await seedChallenge(nonce);

    const proof = uint8ToBase64(await signVaultChallenge(new Uint8Array(nonce), USER_ID, wrong.secretKey));
    const res = await buildApp().inject({ method: 'POST', url: '/api/vault/reactivate', payload: { challenge_id: challenge.id, proof } });

    expect(res.statusCode).toBe(401);
    expect((await testPrisma.vaultKeyring.findUniqueOrThrow({ where: { id: activeVault.id } })).disabledAt).toBeNull();
    expect((await testPrisma.vaultKeyring.findUniqueOrThrow({ where: { id: dormantVault.id } })).disabledAt).toEqual(dormantVault.disabledAt);
  });
});

describe('PUT /api/vault/items/:itemId (optimistic concurrency)', () => {
  let sm: Awaited<ReturnType<typeof signedManifest>>;

  beforeAll(async () => {
    // The vault's identity IS the user's identity, so the same key signs the
    // manifest and the request proof.
    sm = await signedManifest(requestIdentity);
  });

  const body = (lastKnown: number | null) => ({
    item: { item_id: 'tofu:bob', type: 'tofu', ciphertext: 'CT', revision_date_millis: 9000 },
    last_known_revision_date_millis: lastKnown,
    manifest: sm.manifest,
    manifest_sig: sm.manifest_sig,
    revision: 4,
  });

  // Active vault + its identity, so the manifest-signature check passes. Returns
  // the active keyring plus a dormant one, which no write must ever touch.
  async function activeVault(options: { revision?: number; itemRevisionDateMillis?: number } = {}) {
    const identity = await seedRequestIdentity();
    const active = await seedVault({
      identityId: identity.id,
      revision: options.revision ?? 3,
      items:
        options.itemRevisionDateMillis === undefined
          ? []
          : [{ itemId: 'tofu:bob', type: 'tofu', ciphertext: 'OLDCT', revisionDateMillis: options.itemRevisionDateMillis }],
    });
    const dormant = await seedVault({
      identityId: identity.id,
      disabledAt: new Date(),
      revision: 3,
      items: [{ itemId: 'tofu:bob', type: 'tofu', ciphertext: 'DORMANT', revisionDateMillis: 1000 }],
    });

    return { active, dormant };
  }

  async function putItem(payload: object) {
    return buildApp().inject({
      method: 'PUT',
      url: '/api/vault/items/tofu:bob',
      payload,
      headers: await sigHeaders('PUT', '/api/vault/items/tofu:bob', JSON.stringify(payload)),
    });
  }

  it('accepts a write when the client saw the current revision', async () => {
    // The account sits at revision 3, so a write declaring revision 4 advances it
    // by exactly one and the CAS matches.
    const { active, dormant } = await activeVault({ revision: 3, itemRevisionDateMillis: 1000 });

    const res = await putItem(body(1000));

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ revision: 4 });
    // A successful write wakes the user's other devices (server-push).
    expect(notifyVaultChanged).toHaveBeenCalledWith(USER_ID, 4);
    // The account revision advanced and the signed manifest was stored with it.
    const meta = await testPrisma.vaultMeta.findUniqueOrThrow({ where: { vaultId: active.id } });
    expect(meta.accountRevision).toBe(4);
    expect(meta.manifest).toBe(sm.manifest);
    expect(uint8ToBase64(meta.manifestSig)).toBe(sm.manifest_sig);
    // The item itself was written, scoped to the active vault.
    const item = await testPrisma.vaultItem.findUniqueOrThrow({ where: { vaultId_itemId: { vaultId: active.id, itemId: 'tofu:bob' } } });
    expect(item.ciphertext).toBe('CT');
    expect(item.revisionDate.getTime()).toBe(9000);
    // The dormant vault (same user, same item id) was not touched.
    const dormantItem = await testPrisma.vaultItem.findUniqueOrThrow({ where: { vaultId_itemId: { vaultId: dormant.id, itemId: 'tofu:bob' } } });
    expect(dormantItem.ciphertext).toBe('DORMANT');
    expect((await testPrisma.vaultMeta.findUniqueOrThrow({ where: { vaultId: dormant.id } })).accountRevision).toBe(3);
  });

  it('rejects a write that is out of date with 409', async () => {
    const { active } = await activeVault({ revision: 3, itemRevisionDateMillis: 5000 });

    const res = await putItem(body(1000));

    expect(res.statusCode).toBe(409);
    expect(res.json().code).toBe(API_ERROR_VAULT_ITEM_OUT_OF_DATE);
    // Neither the item nor the account revision moved.
    const item = await testPrisma.vaultItem.findUniqueOrThrow({ where: { vaultId_itemId: { vaultId: active.id, itemId: 'tofu:bob' } } });
    expect(item.ciphertext).toBe('OLDCT');
    expect(item.revisionDate.getTime()).toBe(5000);
    expect((await testPrisma.vaultMeta.findUniqueOrThrow({ where: { vaultId: active.id } })).accountRevision).toBe(3);
  });

  it('rejects a write that does not advance the account revision by exactly one (409)', async () => {
    // The item is current, but a concurrent write already moved the account to 4,
    // so this write (revision 4, expecting a base of 3) must lose and re-sync. The
    // conditional CAS matches no row still at revision 3, so no row is updated.
    const { active } = await activeVault({ revision: 4, itemRevisionDateMillis: 1000 });

    const res = await putItem(body(1000));

    expect(res.statusCode).toBe(409);
    expect(res.json().code).toBe(API_ERROR_VAULT_ITEM_OUT_OF_DATE);
    const item = await testPrisma.vaultItem.findUniqueOrThrow({ where: { vaultId_itemId: { vaultId: active.id, itemId: 'tofu:bob' } } });
    expect(item.ciphertext).toBe('OLDCT');
    expect((await testPrisma.vaultMeta.findUniqueOrThrow({ where: { vaultId: active.id } })).accountRevision).toBe(4);
  });

  it('rejects a write whose signed manifest declares a different revision (400)', async () => {
    const { active } = await activeVault({ revision: 3, itemRevisionDateMillis: 1000 });

    // Body claims revision 5 but carries the revision-4 signed manifest.
    const res = await putItem({ ...body(1000), revision: 5 });

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_VAULT_MANIFEST_INVALID);
    const item = await testPrisma.vaultItem.findUniqueOrThrow({ where: { vaultId_itemId: { vaultId: active.id, itemId: 'tofu:bob' } } });
    expect(item.ciphertext).toBe('OLDCT');
    expect((await testPrisma.vaultMeta.findUniqueOrThrow({ where: { vaultId: active.id } })).accountRevision).toBe(3);
  });

  it('rejects a create the client thought was new but already exists', async () => {
    const { active } = await activeVault({ revision: 3, itemRevisionDateMillis: 1000 });

    const res = await putItem(body(null));

    expect(res.statusCode).toBe(409);
    expect((await testPrisma.vaultItem.findUniqueOrThrow({ where: { vaultId_itemId: { vaultId: active.id, itemId: 'tofu:bob' } } })).ciphertext).toBe(
      'OLDCT'
    );
  });

  it('404s when the user has no active vault', async () => {
    // The identity exists (the request signature verifies) but no keyring does.
    await seedRequestIdentity();

    const res = await putItem(body(1000));

    expect(res.statusCode).toBe(404);
    expect(await testPrisma.vaultItem.count()).toBe(0);
  });
});

describe('GET /api/vault/items (warm-sync pull)', () => {
  it('returns the sealed items + manifest + revision without the wrappedVrk', async () => {
    const identity = await seedRequestIdentity();
    await seedVault({
      identityId: identity.id,
      revision: 5,
      items: [{ itemId: 'tofu:bob', type: 'tofu', ciphertext: 'CT', revisionDateMillis: 9000 }],
    });
    // A dormant vault of the same user must never bleed into the active pull.
    await seedVault({
      identityId: identity.id,
      disabledAt: new Date(),
      revision: 2,
      items: [{ itemId: 'tofu:dormant', type: 'tofu', ciphertext: 'DORMANT', revisionDateMillis: 1000 }],
    });

    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/items', headers: await sigHeaders('GET', '/api/vault/items') });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toMatchObject({ revision: 5, manifest: 'M', manifest_sig: uint8ToBase64(Buffer.from('S')) });
    // Items are read scoped to the active vault's id.
    expect(body.items).toEqual([{ item_id: 'tofu:bob', type: 'tofu', ciphertext: 'CT', revision_date_millis: 9000 }]);
    // The passphrase-brute-forceable artifact is never in this JWT-only response.
    expect(body.wrapped_vrk).toBeUndefined();
  });

  it('reports an empty vault (no active keyring) as revision 0 with no items', async () => {
    const identity = await seedRequestIdentity();
    await seedVault({
      identityId: identity.id,
      disabledAt: new Date(),
      revision: 2,
      items: [{ itemId: 'tofu:dormant', type: 'tofu', ciphertext: 'DORMANT', revisionDateMillis: 1000 }],
    });

    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/items', headers: await sigHeaders('GET', '/api/vault/items') });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ revision: 0, manifest: null, manifest_sig: null, items: [] });
  });
});

describe('identity request-signature middleware', () => {
  // A vault whose content would show up in the response body if a handler ever ran.
  async function vaultWithContent() {
    const identity = await seedRequestIdentity();

    return seedVault({
      identityId: identity.id,
      revision: 5,
      items: [{ itemId: 'tofu:bob', type: 'tofu', ciphertext: 'CT', revisionDateMillis: 9000 }],
    });
  }

  it('rejects a covered route with NO signature (401)', async () => {
    await vaultWithContent();

    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/items' });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe(API_ERROR_VAULT_REQUEST_SIGNATURE_INVALID);
    expect(res.json().items).toBeUndefined();
  });

  it('rejects a signature minted for a DIFFERENT path (401)', async () => {
    await vaultWithContent();

    // A valid proof, but bound to /keyring: it must not authorize /items.
    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/items', headers: await sigHeaders('GET', '/api/vault/keyring') });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe(API_ERROR_VAULT_REQUEST_SIGNATURE_INVALID);
    expect(res.json().items).toBeUndefined();
  });

  it('rejects when the account has no active identity to accept a signature from (401)', async () => {
    // No identity row at all for the user.
    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/items', headers: await sigHeaders('GET', '/api/vault/items') });

    expect(res.statusCode).toBe(401);
  });

  it('rejects a tier-2 request whose signature subject differs from the JWT user (401)', async () => {
    await seedRequestIdentity();

    // JWT authenticates USER_ID (verifyJWT mock), but the signature is minted for a
    // DIFFERENT user: a valid token for one account paired with another's signature.
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
    const vault = await vaultWithContent();

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
    expect((await testPrisma.vaultItem.findUniqueOrThrow({ where: { vaultId_itemId: { vaultId: vault.id, itemId: 'tofu:bob' } } })).ciphertext).toBe(
      'CT'
    );
  });
});

describe('identity migration: a continuity-linked predecessor may still authenticate', () => {
  // Set up an active gen-2 identity cross-signed by a gen-1 predecessor, as real
  // rows. Returns the predecessor keypair so the test can sign as a device still
  // on gen 1.
  async function chain(opts: { supersededMsAgo?: number; prevDisabled?: boolean; badCrossSig?: boolean } = {}) {
    const prev = await generateSignatureKeyPair();
    const active = await generateSignatureKeyPair();

    const payload = encodeIdentityContinuityPayload({ userId: USER_ID, generation: 2, algo: 'ed25519', signaturePublicKeyWire: wireKey(active) });
    const crossSig = opts.badCrossSig ? new Uint8Array(64) : await signDetached(payload, prev.secretKey);

    const previous = await seedIdentity(prev, { generation: 1, disabledAt: opts.prevDisabled ? new Date() : null });
    // The active (successor) row's createdAt IS when the predecessor was superseded.
    await seedIdentity(active, {
      generation: 2,
      createdAt: new Date(Date.now() - (opts.supersededMsAgo ?? 24 * 60 * 60 * 1000)),
      previousIdentityId: previous.id,
      continuitySignature: crossSig,
    });

    return prev;
  }

  it('accepts a request signed by an in-window, cross-signed predecessor', async () => {
    const prev = await chain({ supersededMsAgo: 24 * 60 * 60 * 1000 }); // 1 day ago

    // No keyring at all, so a 200 proves the auth walk passed (empty vault body).
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
    // The current vault on the standard params + an older DORMANT vault on heavier
    // params, plus a dormant duplicate. Restore must be able to try each distinct set.
    const identity = await seedRequestIdentity();
    await seedVault({ identityId: identity.id, kdfOps: 3, kdfMem: 64 * 1024 * 1024 });
    await seedVault({ identityId: identity.id, disabledAt: new Date(), kdfOps: 5, kdfMem: 128 * 1024 * 1024 });
    await seedVault({ identityId: identity.id, disabledAt: new Date(), kdfOps: 3, kdfMem: 64 * 1024 * 1024 }); // duplicate, collapsed

    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/meta' });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      kdf_variants: [
        { kdf_ops: 3, kdf_mem: 64 * 1024 * 1024 },
        { kdf_ops: 5, kdf_mem: 128 * 1024 * 1024 },
      ],
    });
  });

  it('never leaks the params of a dormant emergency credential', async () => {
    // An emergency credential whose recovery is not granted is not unlockable, so
    // its (distinct) params must not even hint that the credential exists.
    const identity = await seedRequestIdentity();
    const vault = await seedVault({ identityId: identity.id, kdfOps: 3, kdfMem: 64 * 1024 * 1024 });

    await testPrisma.vaultCredential.create({
      data: {
        vaultId: vault.id,
        type: 'emergency',
        wrappedVrk: 'EMERGENCY',
        authPublicKey: Buffer.from(new Uint8Array(32).fill(1)),
        authPubSig: Buffer.from(new Uint8Array(64)),
        kdfOps: 7,
        kdfMem: 256 * 1024 * 1024,
        lang: 'english',
      },
    });

    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/meta' });

    // Only the unlockable PRIMARY credential's params (3 / 64MB) come back. The
    // dormant emergency credential's DISTINCT params (7 / 256MB) are filtered out
    // by unlockableCredentials, so they must be absent from the response.
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ kdf_variants: [{ kdf_ops: 3, kdf_mem: 64 * 1024 * 1024 }] });
    expect(res.json().kdf_variants).not.toContainEqual({ kdf_ops: 7, kdf_mem: 256 * 1024 * 1024 });
  });

  it('404s only when the user has NO keyring at all', async () => {
    const res = await buildApp().inject({ method: 'GET', url: '/api/vault/meta' });

    expect(res.statusCode).toBe(404);
    expect(res.json().code).toBe(API_ERROR_VAULT_NOT_FOUND);
  });
});

describe('POST /api/vault (atomic onboarding)', () => {
  const bootstrapBody = {
    registration: { challenge_id: '00000000-0000-0000-0000-000000000000', response: 'AA', challenge_signature: 'BB' },
    // KDF params must be the server-pinned standard (DEFAULT_KDF_PARAMS): ops 3, mem 64 MiB.
    keyring: { wrapped_vrk: 'W', auth_public_key: 'A', auth_pub_sig: 'S', kdf_ops: KDF.ops, kdf_mem: KDF.mem, lang: 'en' },
    items: [{ item_id: 'active', type: 'active', ciphertext: 'CT', revision_date_millis: 1 }],
    manifest: 'M',
    manifest_sig: 'MS',
  };

  // A valid dual-key proof, backed by a real pending challenge row, so the
  // onboarding transaction runs to success. The HMAC check is a plain memcmp, so
  // any matching bytes pass; a real signature key signs the challenge id.
  async function successfulOnboardingBody(version = 1) {
    const signature = await generateSignatureKeyPair();
    const hmac = new Uint8Array(32).fill(7);

    const challenge = await testPrisma.keyPossessionChallenge.create({
      data: {
        userId: USER_ID,
        encryptionPublicKey: Buffer.from(`fresh-enc-${version}`),
        signaturePublicKey: Buffer.from(wireKey(signature)),
        keyBindingSignature: Buffer.from('binding'),
        version,
        signedCreatedAt: new Date(1),
        expectedHmac: Buffer.from(hmac),
        expiresAt: new Date(Date.now() + 60000),
      },
    });

    const challengeSig = uint8ToBase64(await signDetached(encodePopChallengeMessage(challenge.id), signature.secretKey));

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
      registration: { challenge_id: challenge.id, response: uint8ToBase64(hmac), challenge_signature: challengeSig },
    };
  }

  it('rejects (400, no vault writes) when the keyring KDF params are not the pinned standard', async () => {
    // A weak / non-standard KDF cost: pinning rejects it (checked before the proof)
    // so no brute-forceable or param-mismatched vault is ever stored. Uses the
    // static body so no challenge row is needed at all.
    const tampered = { ...bootstrapBody, keyring: { ...bootstrapBody.keyring, kdf_ops: 1 } };

    const res = await buildApp().inject({ method: 'POST', url: '/api/vault', payload: tampered });

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_VAULT_KDF_PARAMS_INVALID);
    expect(await testPrisma.vaultKeyring.count()).toBe(0);
    expect(await testPrisma.encryptionKey.count()).toBe(0);
  });

  it('refuses to onboard (no vault writes) when the registration proof is invalid', async () => {
    // No challenge on record, so proof of possession fails before any write.
    const res = await buildApp().inject({ method: 'POST', url: '/api/vault', payload: bootstrapBody });

    expect(res.statusCode).toBe(404);
    expect(res.json().code).toBe(API_ERROR_CHALLENGE_NOT_FOUND);
    // The whole point of the fold: keys OR vault, never a half-written state.
    expect(await testPrisma.vaultKeyring.count()).toBe(0);
    expect(await testPrisma.vaultItem.count()).toBe(0);
    expect(await testPrisma.encryptionKey.count()).toBe(0);
    expect(await testPrisma.identity.count()).toBe(0);
  });

  it('supersedes the current vault (never deletes it) and creates a new active one', async () => {
    // A complete existing account: identity, its encryption key, and an active
    // vault with content.
    const previousIdentity = await seedRequestIdentity();
    await seedEncryptionKey({ identityId: previousIdentity.id, version: 1 });
    const previousVault = await seedVault({
      identityId: previousIdentity.id,
      revision: 7,
      items: [{ itemId: 'tofu:old', type: 'tofu', ciphertext: 'OLDCT', revisionDateMillis: 1000 }],
    });

    const body = await successfulOnboardingBody(2); // next monotonic key version

    const res = await buildApp().inject({ method: 'POST', url: '/api/vault', payload: body });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ revision: 1 });

    // The previous active vault is marked dormant, not deleted, and keeps its
    // content so its own recovery phrase can still recover it.
    const previous = await testPrisma.vaultKeyring.findUniqueOrThrow({ where: { id: previousVault.id } });
    expect(previous.disabledAt).not.toBeNull();
    expect(await testPrisma.vaultItem.count({ where: { vaultId: previousVault.id } })).toBe(1);
    expect((await testPrisma.vaultMeta.findUniqueOrThrow({ where: { vaultId: previousVault.id } })).accountRevision).toBe(7);

    // The fresh vault is the only active one, and carries its own items + meta.
    const fresh = await testPrisma.vaultKeyring.findFirstOrThrow({ where: { userId: USER_ID, disabledAt: null } });
    expect(fresh.id).not.toBe(previousVault.id);
    // Its ONE primary credential carries the freshly wrapped VRK.
    const freshCredentials = await testPrisma.vaultCredential.findMany({ where: { vaultId: fresh.id } });
    expect(freshCredentials).toHaveLength(1);
    expect(freshCredentials[0]).toMatchObject({ type: 'primary', wrappedVrk: 'W' });
    const freshMeta = await testPrisma.vaultMeta.findUniqueOrThrow({ where: { vaultId: fresh.id } });
    expect(freshMeta.accountRevision).toBe(1);
    expect(freshMeta.manifest).toBe(body.manifest);
    const freshItems = await testPrisma.vaultItem.findMany({ where: { vaultId: fresh.id } });
    expect(freshItems).toHaveLength(1);
    expect(freshItems[0]).toMatchObject({ itemId: 'active', type: 'active', ciphertext: 'CT' });

    // The directory registered the new identity + its encryption key, atomically.
    expect(await testPrisma.identity.count({ where: { userId: USER_ID, disabledAt: null } })).toBe(1);
    expect(fresh.identityId).toBe((await testPrisma.identity.findFirstOrThrow({ where: { userId: USER_ID, disabledAt: null } })).id);
    expect(await testPrisma.encryptionKey.count({ where: { userId: USER_ID, disabledAt: null } })).toBe(1);
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
    expect(await testPrisma.vaultKeyring.count()).toBe(0);
    expect(await testPrisma.identity.count()).toBe(0);
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
    expect(await testPrisma.vaultKeyring.count()).toBe(0);
    expect(await testPrisma.identity.count()).toBe(0);
  });
});

describe('PUT /api/vault/keyring (phrase change, burn + re-arm gate)', () => {
  // A keyring body whose auth verifier is genuinely bound to the vault identity
  // (the request-signing identity doubles as the vault identity here).
  async function keyringBody() {
    const authKeyPair = await generateSignatureKeyPair();
    const authPubSig = await signAuthPublicKeyBinding(authKeyPair.publicKey, requestIdentity.secretKey);

    return {
      wrapped_vrk: 'W2',
      auth_public_key: uint8ToBase64(authKeyPair.publicKey),
      auth_pub_sig: uint8ToBase64(authPubSig),
      kdf_ops: KDF.ops,
      kdf_mem: KDF.mem,
      lang: 'english',
    };
  }

  // The account this route operates on: the active vault (its identity is the
  // request-signing one) carrying its primary credential.
  async function ownerVault() {
    const identity = await seedRequestIdentity();

    return seedVault({ identityId: identity.id, wrappedVrk: 'W1', revision: 3 });
  }

  // A re-arm entry signed by the vault identity with real crypto everywhere the
  // server verifies (credential binding + escrow signature over the hashes).
  async function rearmEntry(emergencyAccessId: string, waitTimeDays: number, pinnedIdentityWire?: Uint8Array) {
    const authKeyPair = await generateSignatureKeyPair();
    const authPubSig = await signAuthPublicKeyBinding(authKeyPair.publicKey, requestIdentity.secretKey);
    const capsule = new Uint8Array(randomBytes(64));
    const escrowCreatedAtMillis = Date.now();
    const granteeIdentityWire = pinnedIdentityWire ?? new Uint8Array(33).fill(9);

    const signature = await signEmergencyEscrow(
      {
        grantorUserId: USER_ID,
        granteeUserId: GRANTEE_ID,
        granteeIdentityPublicKeyWire: granteeIdentityWire,
        waitTimeDays,
        escrowCreatedAtMillis,
        credentialAuthPublicKeyHash: await sha256(authKeyPair.publicKey),
        capsuleHash: await sha256(capsule),
      },
      requestIdentity.secretKey
    );

    return {
      emergency_access_id: emergencyAccessId,
      credential: {
        wrapped_vrk: 'EW',
        auth_public_key: uint8ToBase64(authKeyPair.publicKey),
        auth_pub_sig: uint8ToBase64(authPubSig),
        kdf_ops: KDF.ops,
        kdf_mem: KDF.mem,
        lang: 'english',
      },
      grantee_identity_public_key: uint8ToBase64(granteeIdentityWire),
      grantee_key_version: 1,
      wrapped_phrase_for_grantee: uint8ToBase64(capsule),
      escrow_signature: uint8ToBase64(signature),
      escrow_created_at_millis: escrowCreatedAtMillis,
    };
  }

  // A relationship whose recovery is granted: the contact has (or may have) seen
  // the emergency phrase, so this phrase change must burn it.
  async function grantedEscrow(vaultId: string) {
    return seedEmergencyAccess({
      vaultId,
      wrappedVrk: 'REVEALED',
      status: 'recoveryApproved',
      waitTimeDays: 15,
      recoveryRequestedAt: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000),
    });
  }

  async function putKeyring(payload: object) {
    return buildApp().inject({
      method: 'PUT',
      url: '/api/vault/keyring',
      payload,
      headers: await sigHeaders('PUT', '/api/vault/keyring', JSON.stringify(payload)),
    });
  }

  it('re-wraps the primary credential in place when no recovery is granted', async () => {
    const vault = await ownerVault();
    const body = await keyringBody();

    const res = await putKeyring(body);

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ updated: true, rearmed: 0 });
    // The same row was rewritten, not replaced, and it is still the only keyslot.
    const credentials = await testPrisma.vaultCredential.findMany({ where: { vaultId: vault.id } });
    expect(credentials).toHaveLength(1);
    expect(credentials[0]).toMatchObject({ type: 'primary', wrappedVrk: 'W2' });
    expect(uint8ToBase64(credentials[0].authPublicKey)).toBe(body.auth_public_key);
  });

  it('REFUSES a phrase change that does not burn + re-arm a granted escrow', async () => {
    const vault = await ownerVault();
    const { credential } = await grantedEscrow(vault.id);

    const res = await putKeyring(await keyringBody());

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_EMERGENCY_REARM_REQUIRED);
    // Nothing rotated: the old phrase still opens the vault, the revealed
    // emergency keyslot is still there (the user must re-arm, not lose contacts).
    expect((await primaryCredentialOf(vault.id)).wrappedVrk).toBe('W1');
    expect(await testPrisma.vaultCredential.count({ where: { id: credential.id } })).toBe(1);
  });

  it('burns the revealed credential and re-arms the relationship atomically with the rotation', async () => {
    const vault = await ownerVault();
    const { credential, access } = await grantedEscrow(vault.id);
    const entry = await rearmEntry(access.id, 15);
    const body = { ...(await keyringBody()), emergency_rearms: [entry] };

    const res = await putKeyring(body);

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ updated: true, rearmed: 1 });
    // The primary keyslot moved to the new phrase...
    expect((await primaryCredentialOf(vault.id)).wrappedVrk).toBe('W2');
    // ...the revealed emergency keyslot is destroyed...
    expect(await testPrisma.vaultCredential.count({ where: { id: credential.id } })).toBe(0);
    // ...and the relationship survives, re-pointed at a fresh dormant keyslot and
    // reset to a plain confirmed state (the granted recovery is closed).
    const row = await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: access.id }, include: { credential: true } });
    expect(row.credentialId).not.toBe(credential.id);
    expect(row.credential).toMatchObject({ vaultId: vault.id, type: 'emergency', wrappedVrk: 'EW' });
    expect(row.status).toBe('confirmed');
    expect(row.recoveryRequestedAt).toBeNull();
    expect(row.wrappedPhraseForGrantee).toBe(entry.wrapped_phrase_for_grantee);
  });

  it('accepts a re-arm whose grantee key version alone changed (advisory metadata)', async () => {
    const vault = await ownerVault();
    const { access } = await grantedEscrow(vault.id);
    const entry = await rearmEntry(access.id, 15);
    // grantee_key_version is NOT inside the binding signature: it only tells the
    // UI which contact key the capsule targets, so changing it must not fail.
    const body = { ...(await keyringBody()), emergency_rearms: [{ ...entry, grantee_key_version: 2 }] };

    const res = await putKeyring(body);

    expect(res.statusCode).toBe(200);
    expect((await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: access.id } })).granteeKeyVersion).toBe(2);
  });

  it('rejects a re-arm whose signed capsule was swapped after signing', async () => {
    const vault = await ownerVault();
    const { credential, access } = await grantedEscrow(vault.id);
    const entry = await rearmEntry(access.id, 15);
    // The capsule IS covered by the escrow signature (through its hash), so a
    // server-side swap of what the contact would receive is detected.
    const tampered = {
      ...(await keyringBody()),
      emergency_rearms: [{ ...entry, wrapped_phrase_for_grantee: uint8ToBase64(new Uint8Array(64).fill(1)) }],
    };

    const res = await putKeyring(tampered);

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_EMERGENCY_ESCROW_INVALID);
    // The rotation is refused as a whole: nothing burned, nothing re-wrapped.
    expect((await primaryCredentialOf(vault.id)).wrappedVrk).toBe('W1');
    expect(await testPrisma.vaultCredential.count({ where: { id: credential.id } })).toBe(1);
  });

  it('refuses to pin the relationship to an identity that is not the contact’s', async () => {
    const vault = await ownerVault();
    const { access } = await grantedEscrow(vault.id);

    // A registered identity that belongs to a THIRD user. The signature-key column
    // is globally unique, so an unscoped lookup would resolve it happily and store
    // it as this relationship's pinned contact identity, after which GET /trusted
    // would report a stranger's key as the contact's.
    const strangerId = '99999999-9999-4999-8999-999999999999';
    const strangerKey = new Uint8Array(33).fill(7);
    await testPrisma.user.create({ data: { id: strangerId, email: 'stranger@example.org' } });
    await testPrisma.identity.create({ data: { userId: strangerId, generation: 1, signaturePublicKey: Buffer.from(strangerKey) } });

    // Signed by the vault identity over the stranger's key, so the escrow
    // signature itself verifies: only the ownership check can catch this.
    const entry = await rearmEntry(access.id, 15, strangerKey);
    const res = await putKeyring({ ...(await keyringBody()), emergency_rearms: [entry] });

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_EMERGENCY_ESCROW_INVALID);
    expect((await primaryCredentialOf(vault.id)).wrappedVrk).toBe('W1');
  });
});
