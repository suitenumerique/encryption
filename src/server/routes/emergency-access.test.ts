import Fastify from 'fastify';
import { randomBytes, randomUUID } from 'node:crypto';

import { type EmergencyEscrowRecord, sha256, signEmergencyEscrow } from '@encryption/src/crypto/emergency-escrow';
import { base64ToUint8, exportPublicKeyAsBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { REQUEST_SIG_HEADER, signRequestProof } from '@encryption/src/crypto/request-proof';
import { generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import { signAuthPublicKeyBinding } from '@encryption/src/crypto/vault-unlock';
import { testPrisma, useTestDatabase } from '@encryption/src/prisma/testing';
import { sendEmergencyRecoveryRequested } from '@encryption/src/server/email/emergency';
import { emergencyAccessRoute } from '@encryption/src/server/routes/emergency-access';
import {
  API_ERROR_EMERGENCY_ALREADY_EXISTS,
  API_ERROR_EMERGENCY_BAD_STATUS,
  API_ERROR_EMERGENCY_CONTACT_NOT_ONBOARDED,
  API_ERROR_EMERGENCY_ESCROW_INVALID,
  API_ERROR_EMERGENCY_NOT_FOUND,
  API_ERROR_EMERGENCY_SELF_DESIGNATION,
  API_ERROR_RATE_LIMIT_EMERGENCY,
} from '@encryption/src/shared/error-codes';

jest.mock('@encryption/src/server/env', () => ({ env: { EMAIL_PRODUCT_URL: 'http://localhost:7201' } }));

// Shared manual mock: every send is an inert jest.fn; several cases here assert
// on whether a notification was attempted, or make one fail on purpose.
jest.mock('@encryption/src/server/email/emergency');

jest.mock('@encryption/src/prisma/client', () => ({ prisma: jest.requireActual('@encryption/src/prisma/testing').testPrisma }));

useTestDatabase();

// Fixed ids so the escrow payloads (which bind both user ids) can be built
// before any row exists; both users are recreated before every test.
const GRANTOR_ID = '11111111-1111-4111-8111-111111111111';
const GRANTEE_ID = '22222222-2222-4222-8222-222222222222';
const ROW_ID = '33333333-3333-4333-8333-333333333333';
const DAY_MS = 24 * 60 * 60 * 1000;
const KDF = { ops: 3, mem: 64 * 1024 * 1024 };

type SigKeyPair = Awaited<ReturnType<typeof generateSignatureKeyPair>>;

const wireBytes = (pair: SigKeyPair) => base64ToUint8(exportPublicKeyAsBase64(pair.publicKey));

function buildApp(userId: string) {
  const app = Fastify();
  app.decorate('verifyJWT', async (request: { userId?: string }) => {
    request.userId = userId;
  });
  app.register(emergencyAccessRoute);

  return app;
}

async function sigHeaders(identity: SigKeyPair, userId: string, method: string, url: string, body?: string) {
  const token = await signRequestProof({
    method,
    path: url,
    userId,
    identitySecretKey: identity.secretKey,
    nowSeconds: Math.floor(Date.now() / 1000),
    body,
  });

  return { [REQUEST_SIG_HEADER]: token };
}

// A designatable user: the identity the transport auth verifies against, an
// active encryption key, an active vault and its primary credential (the
// language of which decides the notification locale).
async function seedOnboardedUser(userId: string, email: string, identity: SigKeyPair, lang = 'english') {
  await testPrisma.user.create({ data: { id: userId, email } });

  const identityRow = await testPrisma.identity.create({
    data: { userId, generation: 1, signaturePublicKey: Buffer.from(wireBytes(identity)) },
  });

  await testPrisma.encryptionKey.create({
    data: {
      userId,
      identityId: identityRow.id,
      encryptionPublicKey: Buffer.from(`enc-key-${userId}`),
      keyBindingSignature: Buffer.from('binding'),
      version: 1,
    },
  });

  const keyring = await testPrisma.vaultKeyring.create({ data: { userId, identityId: identityRow.id } });

  await testPrisma.vaultCredential.create({ data: { vaultId: keyring.id, type: 'primary', ...credentialMaterial(lang) } });

  return { identityRow, keyring };
}

function credentialMaterial(lang: string) {
  return {
    wrappedVrk: 'WRAPPED',
    authPublicKey: Buffer.from(randomBytes(32)),
    authPubSig: Buffer.from(randomBytes(64)),
    kdfOps: KDF.ops,
    kdfMem: KDF.mem,
    lang,
  };
}

// A relationship as the designation would have left it: a dormant emergency
// credential on the grantor's vault plus the row that owns it.
async function seedRelationship(
  vaultId: string,
  overrides: {
    id?: string;
    granteeUserId?: string;
    status?: 'invited' | 'confirmed' | 'recoveryRequested' | 'recoveryApproved';
    waitTimeDays?: number;
    recoveryRequestedAt?: Date | null;
    lastNotifiedAt?: Date | null;
    granteeKeyVersion?: number;
    createdAt?: Date;
    lang?: string;
  } = {}
) {
  const credential = await testPrisma.vaultCredential.create({
    data: { vaultId, type: 'emergency', ...credentialMaterial(overrides.lang ?? 'french') },
  });

  const row = await testPrisma.emergencyAccess.create({
    data: {
      id: overrides.id ?? ROW_ID,
      grantorUserId: GRANTOR_ID,
      granteeUserId: overrides.granteeUserId ?? GRANTEE_ID,
      status: overrides.status ?? 'invited',
      waitTimeDays: overrides.waitTimeDays ?? 15,
      credentialId: credential.id,
      wrappedPhraseForGrantee: uint8ToBase64(new Uint8Array(randomBytes(64))),
      granteeIdentityId: (await testPrisma.identity.findFirstOrThrow({ where: { signaturePublicKey: Buffer.from(wireBytes(granteeIdentity)) } })).id,
      granteeKeyVersion: overrides.granteeKeyVersion ?? 1,
      escrowSignature: Buffer.from(new Uint8Array(64)),
      escrowCreatedAt: new Date(),
      recoveryRequestedAt: overrides.recoveryRequestedAt ?? null,
      lastNotifiedAt: overrides.lastNotifiedAt ?? null,
      createdAt: overrides.createdAt,
    },
  });

  return { credential, row };
}

// A structurally valid escrow submission signed by the grantor identity, with
// real crypto everywhere the server verifies (auth binding + escrow signature).
async function buildEscrowBody(grantorIdentity: SigKeyPair, granteeIdentityWire: Uint8Array, waitTimeDays: number) {
  const authKey = await generateSignatureKeyPair();
  const authPubSig = await signAuthPublicKeyBinding(authKey.publicKey, grantorIdentity.secretKey);
  const capsule = new Uint8Array(randomBytes(64));
  const escrowCreatedAtMillis = Date.now();

  const record: EmergencyEscrowRecord = {
    grantorUserId: GRANTOR_ID,
    granteeUserId: GRANTEE_ID,
    granteeIdentityPublicKeyWire: granteeIdentityWire,
    waitTimeDays,
    escrowCreatedAtMillis,
    credentialAuthPublicKeyHash: await sha256(authKey.publicKey),
    capsuleHash: await sha256(capsule),
  };
  const signature = await signEmergencyEscrow(record, grantorIdentity.secretKey);

  return {
    grantee_user_id: GRANTEE_ID,
    wait_time_days: waitTimeDays,
    credential: {
      wrapped_vrk: uint8ToBase64(new Uint8Array(randomBytes(48))),
      auth_public_key: uint8ToBase64(authKey.publicKey),
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

let grantorIdentity: SigKeyPair;
let granteeIdentity: SigKeyPair;
let grantorVaultId: string;

beforeAll(async () => {
  grantorIdentity = await generateSignatureKeyPair();
  granteeIdentity = await generateSignatureKeyPair();
});

beforeEach(async () => {
  jest.clearAllMocks();

  const grantor = await seedOnboardedUser(GRANTOR_ID, 'grantor@mail.test', grantorIdentity, 'french');
  await seedOnboardedUser(GRANTEE_ID, 'grantee@mail.test', granteeIdentity, 'english');

  grantorVaultId = grantor.keyring.id;
});

describe('POST /api/emergency-access (designate)', () => {
  it('creates the dormant credential and the invited row from a validly signed escrow', async () => {
    const app = buildApp(GRANTOR_ID);
    const body = await buildEscrowBody(grantorIdentity, wireBytes(granteeIdentity), 15);
    const payload = JSON.stringify(body);

    const res = await app.inject({
      method: 'POST',
      url: '/api/emergency-access',
      payload,
      headers: { 'content-type': 'application/json', ...(await sigHeaders(grantorIdentity, GRANTOR_ID, 'POST', '/api/emergency-access', payload)) },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe('invited');

    const stored = await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: res.json().id }, include: { credential: true } });

    expect(stored.grantorUserId).toBe(GRANTOR_ID);
    expect(stored.granteeUserId).toBe(GRANTEE_ID);
    expect(stored.status).toBe('invited');
    expect(stored.waitTimeDays).toBe(15);
    expect(stored.recoveryRequestedAt).toBeNull();
    expect(stored.credential.type).toBe('emergency');
    expect(stored.credential.vaultId).toBe(grantorVaultId);
    expect(stored.credential.wrappedVrk).toBe(body.credential.wrapped_vrk);
    expect(uint8ToBase64(new Uint8Array(stored.escrowSignature))).toBe(body.escrow_signature);
  });

  it('rejects self-designation', async () => {
    const app = buildApp(GRANTOR_ID);
    const body = { ...(await buildEscrowBody(grantorIdentity, wireBytes(granteeIdentity), 15)), grantee_user_id: GRANTOR_ID };
    const payload = JSON.stringify(body);

    const res = await app.inject({
      method: 'POST',
      url: '/api/emergency-access',
      payload,
      headers: { 'content-type': 'application/json', ...(await sigHeaders(grantorIdentity, GRANTOR_ID, 'POST', '/api/emergency-access', payload)) },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_EMERGENCY_SELF_DESIGNATION);
    expect(await testPrisma.emergencyAccess.count()).toBe(0);
  });

  it('rejects a contact without an active vault', async () => {
    const app = buildApp(GRANTOR_ID);
    const body = await buildEscrowBody(grantorIdentity, wireBytes(granteeIdentity), 15);
    const payload = JSON.stringify(body);

    await testPrisma.vaultKeyring.updateMany({ where: { userId: GRANTEE_ID }, data: { disabledAt: new Date() } });

    const res = await app.inject({
      method: 'POST',
      url: '/api/emergency-access',
      payload,
      headers: { 'content-type': 'application/json', ...(await sigHeaders(grantorIdentity, GRANTOR_ID, 'POST', '/api/emergency-access', payload)) },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_EMERGENCY_CONTACT_NOT_ONBOARDED);
    expect(await testPrisma.emergencyAccess.count()).toBe(0);
  });

  it('rejects a tampered escrow (wait time changed after signing)', async () => {
    const app = buildApp(GRANTOR_ID);
    const body = { ...(await buildEscrowBody(grantorIdentity, wireBytes(granteeIdentity), 15)), wait_time_days: 7 };
    const payload = JSON.stringify(body);

    const res = await app.inject({
      method: 'POST',
      url: '/api/emergency-access',
      payload,
      headers: { 'content-type': 'application/json', ...(await sigHeaders(grantorIdentity, GRANTOR_ID, 'POST', '/api/emergency-access', payload)) },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_EMERGENCY_ESCROW_INVALID);
    expect(await testPrisma.emergencyAccess.count()).toBe(0);
    expect(await testPrisma.vaultCredential.count({ where: { type: 'emergency' } })).toBe(0);
  });

  it('rejects an escrow pinned to a stale contact identity', async () => {
    const app = buildApp(GRANTOR_ID);
    const stale = await generateSignatureKeyPair();
    const body = await buildEscrowBody(grantorIdentity, wireBytes(stale), 15);
    const payload = JSON.stringify(body);

    const res = await app.inject({
      method: 'POST',
      url: '/api/emergency-access',
      payload,
      headers: { 'content-type': 'application/json', ...(await sigHeaders(grantorIdentity, GRANTOR_ID, 'POST', '/api/emergency-access', payload)) },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_EMERGENCY_ESCROW_INVALID);
    expect(await testPrisma.emergencyAccess.count()).toBe(0);
  });

  it('refuses a second designation of the same contact, rolling back the credential it had started', async () => {
    const app = buildApp(GRANTOR_ID);

    async function designate() {
      const body = await buildEscrowBody(grantorIdentity, wireBytes(granteeIdentity), 15);
      const payload = JSON.stringify(body);

      return app.inject({
        method: 'POST',
        url: '/api/emergency-access',
        payload,
        headers: { 'content-type': 'application/json', ...(await sigHeaders(grantorIdentity, GRANTOR_ID, 'POST', '/api/emergency-access', payload)) },
      });
    }

    expect((await designate()).statusCode).toBe(200);

    const second = await designate();

    expect(second.statusCode).toBe(409);
    expect(second.json().code).toBe(API_ERROR_EMERGENCY_ALREADY_EXISTS);
    // The unique (grantor, grantee) fired inside the transaction, so the second
    // emergency credential must not have survived it.
    expect(await testPrisma.emergencyAccess.count()).toBe(1);
    expect(await testPrisma.vaultCredential.count({ where: { type: 'emergency' } })).toBe(1);
  });

  it('counts ATTEMPTS, so revoking does not refund quota', async () => {
    // The durable row count alone is bypassable: either party can delete a
    // relationship, so designate -> revoke -> designate would loop forever, and
    // every cycle mails the target a designation plus a revocation notice. The
    // attempt counter is per-app, so all the calls must go through ONE instance.
    const app = buildApp(GRANTOR_ID);

    const post = async () => {
      const body = await buildEscrowBody(grantorIdentity, wireBytes(granteeIdentity), 15);
      const payload = JSON.stringify(body);

      return app.inject({
        method: 'POST',
        url: '/api/emergency-access',
        payload,
        headers: { 'content-type': 'application/json', ...(await sigHeaders(grantorIdentity, GRANTOR_ID, 'POST', '/api/emergency-access', payload)) },
      });
    };

    // Designate then immediately revoke, ten times over: the table is empty at
    // every step, so a row-count limiter would never trip.
    for (let index = 0; index < 10; index++) {
      expect((await post()).statusCode).toBe(200);
      await testPrisma.emergencyAccess.deleteMany({ where: { grantorUserId: GRANTOR_ID } });
    }

    expect(await testPrisma.emergencyAccess.count({ where: { grantorUserId: GRANTOR_ID } })).toBe(0);

    const res = await post();

    expect(res.statusCode).toBe(429);
    expect(res.json().code).toBe(API_ERROR_RATE_LIMIT_EMERGENCY);
  });

  it('caps designations over the rolling window (the durable row count is a restart-surviving backstop)', async () => {
    const app = buildApp(GRANTOR_ID);

    for (let index = 0; index < 10; index++) {
      const contact = await testPrisma.user.create({ data: { email: `filler-${index}@mail.test` } });

      await seedRelationship(grantorVaultId, { id: randomUUID(), granteeUserId: contact.id, status: 'confirmed' });
    }

    const body = await buildEscrowBody(grantorIdentity, wireBytes(granteeIdentity), 15);
    const payload = JSON.stringify(body);

    const res = await app.inject({
      method: 'POST',
      url: '/api/emergency-access',
      payload,
      headers: { 'content-type': 'application/json', ...(await sigHeaders(grantorIdentity, GRANTOR_ID, 'POST', '/api/emergency-access', payload)) },
    });

    expect(res.statusCode).toBe(429);
    expect(res.json().code).toBe(API_ERROR_RATE_LIMIT_EMERGENCY);
    expect(await testPrisma.emergencyAccess.count({ where: { granteeUserId: GRANTEE_ID } })).toBe(0);
  });
});

describe('POST /:id/accept', () => {
  it('flips invited to confirmed for the designated contact', async () => {
    const app = buildApp(GRANTEE_ID);
    await seedRelationship(grantorVaultId, { status: 'invited' });

    const res = await app.inject({ method: 'POST', url: `/api/emergency-access/${ROW_ID}/accept` });

    expect(res.statusCode).toBe(200);
    expect((await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: ROW_ID } })).status).toBe('confirmed');
  });

  it('is invisible to anyone but the designated contact', async () => {
    const app = buildApp(GRANTOR_ID);
    await seedRelationship(grantorVaultId, { status: 'invited' });

    const res = await app.inject({ method: 'POST', url: `/api/emergency-access/${ROW_ID}/accept` });

    expect(res.statusCode).toBe(404);
    expect(res.json().code).toBe(API_ERROR_EMERGENCY_NOT_FOUND);
    expect((await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: ROW_ID } })).status).toBe('invited');
  });

  it('rejects a double accept', async () => {
    const app = buildApp(GRANTEE_ID);
    await seedRelationship(grantorVaultId, { status: 'confirmed' });

    const res = await app.inject({ method: 'POST', url: `/api/emergency-access/${ROW_ID}/accept` });

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_EMERGENCY_BAD_STATUS);
  });
});

describe('POST /:id/initiate (contact-signed)', () => {
  it('requires an identity signature (JWT alone is rejected)', async () => {
    const app = buildApp(GRANTEE_ID);
    await seedRelationship(grantorVaultId, { status: 'confirmed' });

    const res = await app.inject({ method: 'POST', url: `/api/emergency-access/${ROW_ID}/initiate` });

    expect(res.statusCode).toBe(401);
    expect((await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: ROW_ID } })).status).toBe('confirmed');
  });

  it('starts the wait and stamps the request when the notification email succeeds', async () => {
    const app = buildApp(GRANTEE_ID);
    await seedRelationship(grantorVaultId, { status: 'confirmed' });

    const url = `/api/emergency-access/${ROW_ID}/initiate`;
    const res = await app.inject({ method: 'POST', url, headers: await sigHeaders(granteeIdentity, GRANTEE_ID, 'POST', url) });

    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe('recoveryRequested');
    expect(sendEmergencyRecoveryRequested).toHaveBeenCalled();

    const stored = await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: ROW_ID } });

    expect(stored.status).toBe('recoveryRequested');
    expect(stored.recoveryRequestedAt).not.toBeNull();
    expect(stored.lastNotifiedAt).not.toBeNull();
    expect(res.json().deadline_millis).toBe(stored.recoveryRequestedAt!.getTime() + 15 * DAY_MS);
  });

  it('fails the whole call, leaving the row untouched, when the grantor cannot be notified', async () => {
    const app = buildApp(GRANTEE_ID);
    await seedRelationship(grantorVaultId, { status: 'confirmed' });
    (sendEmergencyRecoveryRequested as jest.Mock).mockRejectedValueOnce(new Error('smtp down'));

    const url = `/api/emergency-access/${ROW_ID}/initiate`;
    const res = await app.inject({ method: 'POST', url, headers: await sigHeaders(granteeIdentity, GRANTEE_ID, 'POST', url) });

    expect(res.statusCode).toBe(500);

    const stored = await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: ROW_ID } });

    expect(stored.status).toBe('confirmed');
    expect(stored.recoveryRequestedAt).toBeNull();
  });

  it('caps repeated initiations of a contact over the rolling window', async () => {
    const app = buildApp(GRANTEE_ID);
    await seedRelationship(grantorVaultId, { status: 'confirmed' });

    const url = `/api/emergency-access/${ROW_ID}/initiate`;
    const call = async () => app.inject({ method: 'POST', url, headers: await sigHeaders(granteeIdentity, GRANTEE_ID, 'POST', url) });

    // The first one starts the recovery, the next ones bounce on the status, and
    // all of them consume the in-memory allowance (checked before anything else).
    expect((await call()).statusCode).toBe(200);
    for (let index = 0; index < 4; index++) expect((await call()).statusCode).toBe(400);

    const res = await call();

    expect(res.statusCode).toBe(429);
    expect(res.json().code).toBe(API_ERROR_RATE_LIMIT_EMERGENCY);
  });
});

describe('reject / cancel', () => {
  it('the grantor can reject with a bare JWT, even after auto-approval', async () => {
    const app = buildApp(GRANTOR_ID);
    await seedRelationship(grantorVaultId, {
      status: 'recoveryApproved',
      recoveryRequestedAt: new Date(Date.now() - 20 * DAY_MS),
      lastNotifiedAt: new Date(),
    });

    const res = await app.inject({ method: 'POST', url: `/api/emergency-access/${ROW_ID}/reject` });

    expect(res.statusCode).toBe(200);

    const stored = await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: ROW_ID } });

    expect(stored.status).toBe('confirmed');
    expect(stored.recoveryRequestedAt).toBeNull();
    expect(stored.lastNotifiedAt).toBeNull();
  });

  it('the contact can cancel their own running request', async () => {
    const app = buildApp(GRANTEE_ID);
    await seedRelationship(grantorVaultId, { status: 'recoveryRequested', recoveryRequestedAt: new Date(), lastNotifiedAt: new Date() });

    const res = await app.inject({ method: 'POST', url: `/api/emergency-access/${ROW_ID}/cancel` });

    expect(res.statusCode).toBe(200);

    const stored = await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: ROW_ID } });

    expect(stored.status).toBe('confirmed');
    expect(stored.recoveryRequestedAt).toBeNull();
    expect(stored.lastNotifiedAt).toBeNull();
  });
});

describe('POST /:id/recover (contact-signed release)', () => {
  it('releases the capsule after the deadline, lazily flipping the status', async () => {
    const app = buildApp(GRANTEE_ID);
    const { row } = await seedRelationship(grantorVaultId, {
      status: 'recoveryRequested',
      recoveryRequestedAt: new Date(Date.now() - 16 * DAY_MS),
      lang: 'french',
    });

    const url = `/api/emergency-access/${ROW_ID}/recover`;
    const res = await app.inject({ method: 'POST', url, headers: await sigHeaders(granteeIdentity, GRANTEE_ID, 'POST', url) });

    expect(res.statusCode).toBe(200);

    const body = res.json();

    expect(body.lang).toBe('french');
    expect(body.escrow.wrapped_phrase_for_grantee).toBe(row.wrappedPhraseForGrantee);
    expect((await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: ROW_ID } })).status).toBe('recoveryApproved');
  });

  it('refuses before the deadline: the arithmetic, not the cron, is the authority', async () => {
    const app = buildApp(GRANTEE_ID);
    await seedRelationship(grantorVaultId, { status: 'recoveryRequested', recoveryRequestedAt: new Date(Date.now() - 2 * DAY_MS) });

    const url = `/api/emergency-access/${ROW_ID}/recover`;
    const res = await app.inject({ method: 'POST', url, headers: await sigHeaders(granteeIdentity, GRANTEE_ID, 'POST', url) });

    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe(API_ERROR_EMERGENCY_BAD_STATUS);
    expect((await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: ROW_ID } })).status).toBe('recoveryRequested');
  });

  it('never releases to the grantor or anyone else', async () => {
    const app = buildApp(GRANTOR_ID);
    await seedRelationship(grantorVaultId, { status: 'recoveryRequested', recoveryRequestedAt: new Date(Date.now() - 16 * DAY_MS) });

    const url = `/api/emergency-access/${ROW_ID}/recover`;
    const res = await app.inject({ method: 'POST', url, headers: await sigHeaders(grantorIdentity, GRANTOR_ID, 'POST', url) });

    expect(res.statusCode).toBe(404);
    expect((await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: ROW_ID } })).status).toBe('recoveryRequested');
  });
});

describe('DELETE /:id', () => {
  it('destroys the credential (the row cascades) for either party', async () => {
    const app = buildApp(GRANTEE_ID);
    const { credential } = await seedRelationship(grantorVaultId, { status: 'confirmed' });

    const res = await app.inject({ method: 'DELETE', url: `/api/emergency-access/${ROW_ID}` });

    expect(res.statusCode).toBe(200);
    expect(await testPrisma.vaultCredential.findUnique({ where: { id: credential.id } })).toBeNull();
    // The relationship carries no lifecycle of its own: the credential is what
    // holds the escrow, and the foreign key cascade takes the row with it.
    expect(await testPrisma.emergencyAccess.findUnique({ where: { id: ROW_ID } })).toBeNull();
  });
});

describe('GET /trusted', () => {
  it('maps rows with deadline and escrow record for the client-side audit', async () => {
    const app = buildApp(GRANTOR_ID);
    const requestedAt = new Date(Date.now() - 3 * DAY_MS);
    const { credential } = await seedRelationship(grantorVaultId, {
      status: 'recoveryRequested',
      recoveryRequestedAt: requestedAt,
      granteeKeyVersion: 2,
    });

    const res = await app.inject({ method: 'GET', url: '/api/emergency-access/trusted' });

    expect(res.statusCode).toBe(200);

    const entry = res.json().contacts[0];

    expect(entry.id).toBe(ROW_ID);
    expect(entry.grantee_email).toBe('grantee@mail.test');
    expect(entry.deadline_millis).toBe(requestedAt.getTime() + 15 * DAY_MS);
    expect(entry.vault_active).toBe(true);
    expect(entry.escrow.grantee_key_version).toBe(2);
    expect(entry.escrow.credential_auth_public_key_hash).toBeTruthy();
    expect(entry.escrow.grantee_identity_public_key).toBe(uint8ToBase64(wireBytes(granteeIdentity)));
    expect(credential.type).toBe('emergency');
  });

  it('reports a disabled grantor vault so the interface can flag a dead escrow', async () => {
    const app = buildApp(GRANTOR_ID);
    await seedRelationship(grantorVaultId, { status: 'confirmed' });
    await testPrisma.vaultKeyring.update({ where: { id: grantorVaultId }, data: { disabledAt: new Date() } });

    const res = await app.inject({ method: 'GET', url: '/api/emergency-access/trusted' });

    expect(res.statusCode).toBe(200);
    expect(res.json().contacts[0].vault_active).toBe(false);
    expect(res.json().contacts[0].deadline_millis).toBeNull();
  });
});
