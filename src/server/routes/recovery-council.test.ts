import Fastify, { type FastifyInstance } from 'fastify';
import { randomBytes } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { rosterFingerprint, verifyRosterChain } from '@encryption/src/crypto/council';
import { signRoster } from '@encryption/src/crypto/council';
import {
  buildContribution,
  buildCouncilEscrow,
  buildReshareKeys,
  buildReshareSubShares,
  escrowRecordFromWire,
  openCustodianShare,
  recoverCouncilSecret,
  rosterRecordFromWire,
  signedVersionFromWire,
} from '@encryption/src/crypto/council-protocol';
import { type HybridKeyPair, ensureSodium, generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { base64ToUint8, exportPublicKeyAsBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { REQUEST_SIG_HEADER, signRequestProof } from '@encryption/src/crypto/request-proof';
import { encodeShare, randomScalar } from '@encryption/src/crypto/shamir';
import { type SignatureKeyPair, generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import { DEFAULT_KDF_PARAMS, signAuthPublicKeyBinding, signVaultChallenge } from '@encryption/src/crypto/vault-unlock';
import { testPrisma, useTestDatabase } from '@encryption/src/prisma/testing';
import { sendCouncilRecoveryRequested, sendCouncilRosterToSign } from '@encryption/src/server/email/council';
import { recoveryCouncilsSchema } from '@encryption/src/server/recovery-councils';
import { recoveryCouncilRoute } from '@encryption/src/server/routes/recovery-council';
import { vaultRoute } from '@encryption/src/server/routes/vault';
import {
  API_ERROR_COUNCIL_ESCROW_INVALID,
  API_ERROR_COUNCIL_MEETING_REQUIRED,
  API_ERROR_COUNCIL_NOT_CUSTODIAN,
  API_ERROR_COUNCIL_REARM_REQUIRED,
  API_ERROR_COUNCIL_REQUEST_EXISTS,
  API_ERROR_COUNCIL_RESHARE_INVALID,
  API_ERROR_COUNCIL_ROSTER_CHANGED,
  API_ERROR_RATE_LIMIT_COUNCIL,
} from '@encryption/src/shared/error-codes';
import type { CouncilCapsuleWire, CouncilEscrowBody, RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';

const env = vi.hoisted(() => ({
  EMAIL_PRODUCT_URL: 'http://localhost:7201',
  OIDC_STEP_UP_ENABLED: false,
  OIDC_STEP_UP_ACR_VALUES: [] as string[],
  OIDC_STEP_UP_AMR_VALUES: [] as string[],
  OIDC_STEP_UP_MAX_AGE_SECONDS: 300,
  RECOVERY_COUNCILS: undefined as unknown,
}));

vi.mock('@encryption/src/server/env', () => ({ env }));
vi.mock('@encryption/src/server/email/council');
vi.mock('@encryption/src/server/email/emergency');
vi.mock('@encryption/src/server/vault-notify', () => ({ addVaultListener: vi.fn(), removeVaultListener: vi.fn(), notifyVaultChanged: vi.fn() }));
vi.mock('@encryption/src/prisma/client', async () => ({
  prisma: (await vi.importActual<typeof import('@encryption/src/prisma/testing')>('@encryption/src/prisma/testing')).testPrisma,
}));

useTestDatabase();

const COUNCIL = 'dinum';

interface Person {
  id: string;
  email: string;
  name: string;
  identity: SignatureKeyPair;
  encryption: HybridKeyPair;
  vaultId: string;
  identityId: string;
}

const wire = (identity: SignatureKeyPair) => base64ToUint8(exportPublicKeyAsBase64(identity.publicKey));

async function seedPerson(n: number, email: string, name: string): Promise<Person> {
  const id = `${n}`.repeat(8) + '-0000-4000-8000-000000000000';
  const identity = await generateSignatureKeyPair();
  const encryption = await generateUserKeyPair();
  const [firstName, lastName] = name.split(' ');

  await testPrisma.user.create({ data: { id, email, firstName, lastName } });
  const identityRow = await testPrisma.identity.create({ data: { userId: id, generation: 1, signaturePublicKey: Buffer.from(wire(identity)) } });
  await testPrisma.encryptionKey.create({
    data: {
      userId: id,
      identityId: identityRow.id,
      encryptionPublicKey: Buffer.from(base64ToUint8(exportPublicKeyAsBase64(encryption.publicKey))),
      keyBindingSignature: Buffer.from('binding'),
      version: 1,
    },
  });
  const keyring = await testPrisma.vaultKeyring.create({ data: { userId: id, identityId: identityRow.id } });
  await testPrisma.vaultCredential.create({
    data: {
      vaultId: keyring.id,
      type: 'primary',
      wrappedVrk: 'WRAPPED',
      authPublicKey: Buffer.from(randomBytes(32)),
      authPubSig: Buffer.from(randomBytes(64)),
      kdfOps: DEFAULT_KDF_PARAMS.opsLimit,
      kdfMem: DEFAULT_KDF_PARAMS.memLimit,
      lang: 'english',
    },
  });

  return { id, email, name, identity, encryption, vaultId: keyring.id, identityId: identityRow.id };
}

function buildApp(): FastifyInstance {
  const app = Fastify();
  app.decorate('verifyIdToken', async (request: { userId?: string; idTokenClaims?: Record<string, unknown>; headers: Record<string, unknown> }) => {
    request.userId = request.headers['x-test-user'] as string;
    request.idTokenClaims = {};
  });
  app.register(recoveryCouncilRoute);
  app.register(vaultRoute);

  return app;
}

let app: FastifyInstance;

async function call<T = Record<string, unknown>>(
  as: Person,
  method: 'GET' | 'POST' | 'PUT',
  url: string,
  body?: unknown,
  options: { signed?: boolean } = {}
): Promise<{ status: number; json: T }> {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  const headers: Record<string, string> = { 'x-test-user': as.id };
  if (payload) headers['content-type'] = 'application/json';
  if (options.signed) {
    headers[REQUEST_SIG_HEADER] = await signRequestProof({
      method,
      path: url,
      userId: as.id,
      identitySecretKey: as.identity.secretKey,
      nowSeconds: Math.floor(Date.now() / 1000),
      body: payload,
    });
  }

  const res = await app.inject({ method, url, headers, payload });

  return { status: res.statusCode, json: res.json() as T };
}

function configure(custodians: Person[], threshold: number) {
  env.RECOVERY_COUNCILS = recoveryCouncilsSchema.parse([
    {
      id: COUNCIL,
      label: 'Équipe sécurité DINUM',
      domains: ['numerique.gouv.fr'],
      custodians: custodians.map((c) => ({ userId: c.id, email: c.email })),
      threshold,
    },
  ]);
}

interface MineCouncil {
  council_id: string;
  role: string;
  configured: boolean;
  my_slot: number | null;
  chain: RosterVersionWire[];
  proposal: { roster: RosterVersionWire; quorum_missing: number; pending_members: Array<{ name: string }>; may_sign: boolean } | null;
  blocked: Array<{ email: string; reason: string }>;
  health: { escrows: number; ok: number; at_risk: number; lost: number; outdated: Array<{ version: number; escrows: number }> };
  requests: Array<{ id: string; stage: string; can_contribute: boolean; my_contribution: string }>;
  reshare: { session_id: string; i_am_helper: boolean; remaining_for_me: number } | null;
}

async function mine(as: Person): Promise<MineCouncil[]> {
  return (await call<{ councils: MineCouncil[] }>(as, 'GET', '/api/councils/mine')).json.councils;
}

/** What a custodian's vault does to sign the proposal it was shown. */
async function signProposal(as: Person): Promise<{ status: number; activated: boolean }> {
  const [council] = await mine(as);
  const roster = council.proposal!.roster;
  const signature = await signRoster(rosterRecordFromWire(COUNCIL, roster), as.identity.secretKey);
  const res = await call<{ activated: boolean }>(
    as,
    'POST',
    `/api/councils/${COUNCIL}/versions/${roster.version}/sign`,
    { signature: uint8ToBase64(signature) },
    { signed: true }
  );

  return { status: res.status, activated: res.json.activated };
}

async function keysBySlot(roster: RosterVersionWire, people: Person[]) {
  return new Map(roster.members.map((m) => [m.slot, people.find((p) => p.id === m.user_id)!.encryption.publicKey]));
}

/** What the user's vault does to enroll: verify the chain, split a fresh secret, sign. */
async function enroll(user: Person, people: Person[]): Promise<{ body: CouncilEscrowBody; secret: Uint8Array; auth: SignatureKeyPair }> {
  const forMe = (await call<{ council: { chain: RosterVersionWire[] } }>(user, 'GET', '/api/councils/for-me')).json;
  const chain = forMe.council.chain.map((v) => signedVersionFromWire(COUNCIL, v));
  const verified = await verifyRosterChain(chain);
  if (!verified.ok) throw new Error(`chain refused: ${verified.reason}`);

  const head = forMe.council.chain[forMe.council.chain.length - 1];
  await ensureSodium();
  const secret = randomScalar();
  const auth = await generateSignatureKeyPair();

  const body = await buildCouncilEscrow({
    userId: user.id,
    head: verified.head,
    custodianKeys: await keysBySlot(head, people),
    secret,
    credential: {
      wrapped_vrk: uint8ToBase64(new Uint8Array(randomBytes(72))),
      auth_public_key: uint8ToBase64(auth.publicKey),
      auth_pub_sig: uint8ToBase64(await signAuthPublicKeyBinding(auth.publicKey, user.identity.secretKey)),
      kdf_ops: DEFAULT_KDF_PARAMS.opsLimit,
      kdf_mem: DEFAULT_KDF_PARAMS.memLimit,
      lang: 'english',
    },
    identitySecretKey: user.identity.secretKey,
    createdAtMillis: Date.now(),
  });

  return { body, secret, auth };
}

/** What a custodian's vault does to hand over its share. */
async function contribute(as: Person, requestId: string, inPerson: boolean) {
  const detail = (
    await call<{
      user_id: string;
      council_id: string;
      ephemeral_public_key: string;
      escrow: Parameters<typeof escrowRecordFromWire>[1];
      capsule: CouncilCapsuleWire;
    }>(as, 'GET', `/api/council-recovery/requests/${requestId}/custodian`)
  ).json;

  const share = await openCustodianShare(detail.capsule, escrowRecordFromWire(detail.user_id, detail.escrow), {
    userId: detail.user_id,
    councilId: detail.council_id,
    secretKeys: [as.encryption.secretKey],
  });

  const body = await buildContribution({
    requestId,
    userId: detail.user_id,
    councilId: detail.council_id,
    slot: detail.capsule.slot,
    custodianUserId: as.id,
    ephemeralPublicKey: base64ToUint8(detail.ephemeral_public_key),
    encodedShare: share,
    inPerson,
    identitySecretKey: as.identity.secretKey,
  });

  return call<{ stage: string; code?: string }>(as, 'POST', `/api/council-recovery/requests/${requestId}/contribute`, body, { signed: true });
}

let alice: Person; // custodian
let bruno: Person; // custodian
let chloe: Person; // custodian
let denis: Person; // newcomer
let ursula: Person; // the user

beforeEach(async () => {
  vi.clearAllMocks();
  app = buildApp();
  alice = await seedPerson(1, 'alice@numerique.gouv.fr', 'Alice Martin');
  bruno = await seedPerson(2, 'bruno@numerique.gouv.fr', 'Bruno Petit');
  chloe = await seedPerson(3, 'chloe@numerique.gouv.fr', 'Chloé Durand');
  denis = await seedPerson(4, 'denis@numerique.gouv.fr', 'Denis Moreau');
  ursula = await seedPerson(5, 'ursula@numerique.gouv.fr', 'Ursula Roux');
});

async function bootstrap(custodians: Person[], threshold: number) {
  configure(custodians, threshold);
  for (const custodian of custodians) await signProposal(custodian);
}

describe('roster governance', () => {
  it('proposes the configured council, which takes effect once every custodian vouched for their own key', async () => {
    configure([alice, bruno, chloe], 2);

    const [invited] = await mine(alice);
    expect(invited.role).toBe('invited');
    expect(invited.proposal?.roster.members.map((m) => m.slot)).toEqual([1, 2, 3]);
    expect(sendCouncilRosterToSign).toHaveBeenCalledTimes(3);

    expect((await signProposal(alice)).activated).toBe(false);
    expect((await signProposal(bruno)).activated).toBe(false);
    expect((await signProposal(chloe)).activated).toBe(true);

    const [council] = await mine(alice);
    expect(council.role).toBe('custodian');
    expect(council.proposal).toBeNull();
    expect((await verifyRosterChain(council.chain.map((v) => signedVersionFromWire(COUNCIL, v)))).ok).toBe(true);
  });

  it('tells nothing to someone who is not in a council', async () => {
    await bootstrap([alice, bruno, chloe], 2);

    expect(await mine(ursula)).toEqual([]);
  });

  it('proposes nothing while a configured email does not match the user id, or someone has no vault', async () => {
    env.RECOVERY_COUNCILS = recoveryCouncilsSchema.parse([
      {
        id: COUNCIL,
        label: 'DINUM',
        domains: ['numerique.gouv.fr'],
        custodians: [
          { userId: alice.id, email: alice.email },
          { userId: bruno.id, email: 'someone-else@numerique.gouv.fr' },
        ],
        threshold: 1,
      },
    ]);

    expect(await mine(alice)).toEqual([]);
    expect(await testPrisma.councilRosterVersion.count()).toBe(0);
  });

  it('replaces a custodian with k signatures of the previous version plus the newcomer, and deletes the leaver’s capsules', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body } = await enroll(ursula, [alice, bruno, chloe]);
    expect((await call(ursula, 'POST', '/api/councils/escrow', body, { signed: true })).status).toBe(200);

    configure([alice, bruno, denis], 2);
    const [proposed] = await mine(denis);
    expect(proposed.role).toBe('invited');
    // Denis gets a slot never used before: Chloé's share stays on slot 3.
    expect(proposed.proposal!.roster.members.map((m) => m.slot)).toEqual([1, 2, 4]);

    expect((await signProposal(denis)).activated).toBe(false);
    expect((await signProposal(alice)).activated).toBe(false);
    expect((await signProposal(bruno)).activated).toBe(true);

    expect(await testPrisma.councilCapsule.count({ where: { slot: 3 } })).toBe(0);

    const [council] = await mine(alice);
    expect(council.health).toMatchObject({ escrows: 1, at_risk: 1, outdated: [{ version: 1, escrows: 1 }] });
    expect(await mine(chloe)).toEqual([]);
  });

  it('refuses a signature over another roster than the one proposed', async () => {
    configure([alice, bruno, chloe], 2);
    const [council] = await mine(alice);
    const forged = { ...rosterRecordFromWire(COUNCIL, council.proposal!.roster), threshold: 1 };

    const res = await call(
      alice,
      'POST',
      `/api/councils/${COUNCIL}/versions/1/sign`,
      { signature: uint8ToBase64(await signRoster(forged, alice.identity.secretKey)) },
      { signed: true }
    );
    expect(res.status).toBe(400);
  });

  it('keeps everything in force when the configuration disappears', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body } = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', body, { signed: true });

    env.RECOVERY_COUNCILS = undefined;

    const [council] = await mine(alice);
    expect(council.configured).toBe(false);
    expect(council.chain).toHaveLength(1);
    expect(council.health).toMatchObject({ escrows: 1, ok: 1, lost: 0 });

    const forMe = (await call<{ escrow: { health: { status: string } } }>(ursula, 'GET', '/api/councils/for-me')).json;
    expect(forMe.escrow.health.status).toBe('ok');
  });

  it('asks for a new version when a custodian started over, and counts their shares as lost meanwhile', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body } = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', body, { signed: true });

    // Bruno starts over: a new identity with no continuity link.
    const fresh = await generateSignatureKeyPair();
    await testPrisma.identity.updateMany({ where: { userId: bruno.id }, data: { disabledAt: new Date() } });
    await testPrisma.identity.create({ data: { userId: bruno.id, generation: 2, signaturePublicKey: Buffer.from(wire(fresh)) } });

    const [council] = await mine(alice);
    expect(council.health).toMatchObject({ at_risk: 1 });
    expect(council.proposal?.roster.members.find((m) => m.user_id === bruno.id)?.slot).toBe(4);
  });
});

describe('enrollment', () => {
  it('refuses an escrow that does not cover exactly the head, or that the user did not sign', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body } = await enroll(ursula, [alice, bruno, chloe]);

    expect((await call(ursula, 'POST', '/api/councils/escrow', { ...body, shares: body.shares.slice(1) }, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_ROSTER_CHANGED,
    });
    expect((await call(ursula, 'POST', '/api/councils/escrow', { ...body, threshold: 1 }, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_ROSTER_CHANGED,
    });
    expect(
      (await call(ursula, 'POST', '/api/councils/escrow', { ...body, escrow_signature: uint8ToBase64(new Uint8Array(64)) }, { signed: true })).json
    ).toMatchObject({ code: API_ERROR_COUNCIL_ESCROW_INVALID });
  });

  it('shows the council and the organization’s fingerprint to compare', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const forMe = (await call<{ council: { chain: RosterVersionWire[]; label: string } }>(ursula, 'GET', '/api/councils/for-me')).json;

    expect(forMe.council.label).toBe('Équipe sécurité DINUM');
    expect(forMe.council.chain[0].members.map((m) => m.name)).toEqual(['Alice Martin', 'Bruno Petit', 'Chloé Durand']);
    expect(await rosterFingerprint(rosterRecordFromWire(COUNCIL, forMe.council.chain[0]))).toMatch(/^1\d{39}$/);
  });
});

describe('recovery', () => {
  async function enrolled() {
    await bootstrap([alice, bruno, chloe], 2);
    const enrollment = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', enrollment.body, { signed: true });

    return enrollment;
  }

  async function ask() {
    const ephemeral = await generateUserKeyPair();
    const ephemeralWire = base64ToUint8(exportPublicKeyAsBase64(ephemeral.publicKey));
    const res = await call<{ id: string }>(ursula, 'POST', '/api/council-recovery/requests', { ephemeral_public_key: uint8ToBase64(ephemeralWire) });
    expect(res.status).toBe(200);

    return { id: res.json.id, ephemeral: { publicKey: ephemeralWire, secretKey: ephemeral.secretKey } };
  }

  it('gives the vault back after remote approvals and one share handed over in person', async () => {
    const { secret, auth } = await enrolled();
    const { id, ephemeral } = await ask();
    expect(sendCouncilRecoveryRequested).toHaveBeenCalledOnce();

    // The user only learns "in progress": no count, no names.
    expect((await call(ursula, 'GET', '/api/council-recovery/requests/mine')).json).toMatchObject({ request: { stage: 'in_progress', meet: [] } });

    expect((await contribute(alice, id, false)).json.stage).toBe('awaiting_meeting');
    expect((await call(ursula, 'GET', '/api/council-recovery/requests/mine')).json).toMatchObject({
      request: { stage: 'meet', meet: [{ name: 'Bruno Petit' }, { name: 'Chloé Durand' }] },
    });

    // A second remote approval would let a stolen login finish alone.
    expect((await contribute(bruno, id, false)).json).toMatchObject({ code: API_ERROR_COUNCIL_MEETING_REQUIRED });
    expect((await contribute(bruno, id, true)).json.stage).toBe('released');

    const released = (await call<Parameters<typeof recoverCouncilSecret>[0]>(ursula, 'GET', `/api/council-recovery/requests/${id}/shares`)).json;
    const recovered = await recoverCouncilSecret(released, ephemeral, wire(ursula.identity));
    expect(recovered.secret).toEqual(secret);
    expect(recovered.contributors.map((c) => c.inPerson)).toEqual([false, true]);

    // The released council credential now opens the vault.
    const challenge = (await call<{ challenge_id: string; nonce: string }>(ursula, 'POST', '/api/vault/challenge')).json;
    const proof = await signVaultChallenge(base64ToUint8(challenge.nonce), ursula.id, auth.secretKey);
    const fetched = await call<{ credential_type: string }>(ursula, 'POST', '/api/vault/fetch', {
      challenge_id: challenge.challenge_id,
      proof: uint8ToBase64(proof),
    });
    expect(fetched.json.credential_type).toBe('council');

    // The forced phrase change must burn it and re-arm the council.
    const newAuth = await generateSignatureKeyPair();
    const keyring = {
      wrapped_vrk: uint8ToBase64(new Uint8Array(randomBytes(72))),
      auth_public_key: uint8ToBase64(newAuth.publicKey),
      auth_pub_sig: uint8ToBase64(await signAuthPublicKeyBinding(newAuth.publicKey, ursula.identity.secretKey)),
      kdf_ops: DEFAULT_KDF_PARAMS.opsLimit,
      kdf_mem: DEFAULT_KDF_PARAMS.memLimit,
      lang: 'english',
    };
    expect((await call(ursula, 'PUT', '/api/vault/keyring', keyring, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_REARM_REQUIRED,
    });

    const rearm = await enroll(ursula, [alice, bruno, chloe]);
    expect((await call(ursula, 'PUT', '/api/vault/keyring', { ...keyring, council_rearm: rearm.body }, { signed: true })).status).toBe(200);

    expect(await testPrisma.councilRequest.count()).toBe(0);
    const escrows = await testPrisma.councilEscrow.findMany();
    expect(escrows).toHaveLength(1);
    expect(new Uint8Array(escrows[0].secretCommitment)).toEqual(base64ToUint8(rearm.body.secret_commitment));
  });

  it('lets the phrase change leave the council when its setup cannot be renewed', async () => {
    await enrolled();
    const { id } = await ask();
    await contribute(alice, id, false);
    await contribute(bruno, id, true);

    const auth = await generateSignatureKeyPair();
    const keyring = {
      wrapped_vrk: uint8ToBase64(new Uint8Array(randomBytes(72))),
      auth_public_key: uint8ToBase64(auth.publicKey),
      auth_pub_sig: uint8ToBase64(await signAuthPublicKeyBinding(auth.publicKey, ursula.identity.secretKey)),
      kdf_ops: DEFAULT_KDF_PARAMS.opsLimit,
      kdf_mem: DEFAULT_KDF_PARAMS.memLimit,
      lang: 'english',
    };

    expect((await call(ursula, 'PUT', '/api/vault/keyring', { ...keyring, council_drop: true }, { signed: true })).status).toBe(200);
    expect(await testPrisma.councilEscrow.count()).toBe(0);
    expect(await testPrisma.vaultCredential.count({ where: { type: 'council' } })).toBe(0);
    // Without a released request there is nothing to renew or leave.
    expect((await call(ursula, 'PUT', '/api/vault/keyring', { ...keyring, council_drop: true }, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_REARM_REQUIRED,
    });
  });

  // A custodian's vault handing over a value that is not its share is caught
  // share by share against the commitments, never combined into a wrong phrase.
  it('refuses a share that does not lie on the commitments', async () => {
    await enrolled();
    const { id, ephemeral } = await ask();
    const detail = (await call<{ user_id: string; ephemeral_public_key: string }>(alice, 'GET', `/api/council-recovery/requests/${id}/custodian`))
      .json;

    const forged = await buildContribution({
      requestId: id,
      userId: detail.user_id,
      councilId: COUNCIL,
      slot: 1,
      custodianUserId: alice.id,
      ephemeralPublicKey: base64ToUint8(detail.ephemeral_public_key),
      encodedShare: encodeShare({ x: 1, value: randomScalar(), blinding: randomScalar() }),
      inPerson: false,
      identitySecretKey: alice.identity.secretKey,
    });
    expect((await call(alice, 'POST', `/api/council-recovery/requests/${id}/contribute`, forged, { signed: true })).status).toBe(200);
    expect((await contribute(bruno, id, true)).json.stage).toBe('released');

    const released = (await call<Parameters<typeof recoverCouncilSecret>[0]>(ursula, 'GET', `/api/council-recovery/requests/${id}/shares`)).json;
    await expect(recoverCouncilSecret(released, ephemeral, wire(ursula.identity))).rejects.toThrow('Not enough valid shares');
  });

  it('does not release without an in-person share, however many approvals', async () => {
    await bootstrap([alice, bruno, chloe, denis], 3);
    const enrollment = await enroll(ursula, [alice, bruno, chloe, denis]);
    await call(ursula, 'POST', '/api/councils/escrow', enrollment.body, { signed: true });
    const { id } = await ask();

    expect((await contribute(alice, id, false)).json.stage).toBe('collecting');
    expect((await contribute(bruno, id, false)).json.stage).toBe('awaiting_meeting');
    expect((await contribute(chloe, id, false)).json).toMatchObject({ code: API_ERROR_COUNCIL_MEETING_REQUIRED });
    expect((await call(ursula, 'GET', `/api/council-recovery/requests/${id}/shares`)).status).toBe(400);
  });

  it('keeps one request at a time, and lets the user refuse it', async () => {
    await enrolled();
    const { id } = await ask();

    expect(
      (await call(ursula, 'POST', '/api/council-recovery/requests', { ephemeral_public_key: uint8ToBase64(new Uint8Array(33)) })).json
    ).toMatchObject({
      code: API_ERROR_COUNCIL_REQUEST_EXISTS,
    });

    await contribute(alice, id, false);
    expect((await call(ursula, 'POST', `/api/council-recovery/requests/${id}/refuse`)).status).toBe(200);
    expect(await testPrisma.councilContribution.count()).toBe(0);
    expect((await call(ursula, 'GET', '/api/council-recovery/requests/mine')).json).toEqual({ request: null });
  });

  // Every request emails the user and the custodians: asking, refusing and asking
  // again is capped.
  it('limits how often a user asks', async () => {
    await enrolled();

    for (let i = 0; i < 3; i++) {
      const { id } = await ask();
      await call(ursula, 'POST', `/api/council-recovery/requests/${id}/refuse`);
    }

    const res = await call(ursula, 'POST', '/api/council-recovery/requests', { ephemeral_public_key: uint8ToBase64(new Uint8Array(33)) });
    expect(res.status).toBe(429);
    expect(res.json).toMatchObject({ code: API_ERROR_RATE_LIMIT_COUNCIL });
  });

  it('lets a custodian stop a request, and refuses outsiders', async () => {
    await enrolled();
    const { id } = await ask();

    expect((await call(denis, 'GET', `/api/council-recovery/requests/${id}/custodian`)).json).toMatchObject({
      code: API_ERROR_COUNCIL_NOT_CUSTODIAN,
    });
    expect((await call(chloe, 'POST', `/api/council-recovery/requests/${id}/abort`, undefined, { signed: true })).json).toEqual({ aborted: true });
    expect((await call(ursula, 'GET', '/api/council-recovery/requests/mine')).json).toEqual({ request: null });
  });

  it('expires a request and closes the released credential with it', async () => {
    const { auth } = await enrolled();
    const { id } = await ask();
    await contribute(alice, id, false);
    await contribute(bruno, id, true);

    await testPrisma.councilRequest.update({ where: { id }, data: { expiresAt: new Date(Date.now() - 1000) } });

    const challenge = (await call<{ challenge_id: string; nonce: string }>(ursula, 'POST', '/api/vault/challenge')).json;
    const proof = await signVaultChallenge(base64ToUint8(challenge.nonce), ursula.id, auth.secretKey);
    expect((await call(ursula, 'POST', '/api/vault/fetch', { challenge_id: challenge.challenge_id, proof: uint8ToBase64(proof) })).status).toBe(401);
  });
});

describe('resharing', () => {
  it('moves an escrow to the new roster without the user, and the newcomer can then help', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body, secret } = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', body, { signed: true });

    configure([alice, bruno, denis], 2);
    await mine(denis);
    await signProposal(denis);
    await signProposal(alice);
    await signProposal(bruno);

    const start = await call<{ session_id: string }>(
      alice,
      'POST',
      `/api/councils/${COUNCIL}/reshare`,
      { source_version: 1, helper_slots: [1, 2] },
      { signed: true }
    );
    expect(start.status).toBe(200);
    const sessionId = start.json.session_id;

    for (const helper of [alice, bruno]) {
      const batch = (
        await call<{
          chain: RosterVersionWire[];
          helper_slots: number[];
          my_slot: number;
          escrows: Array<{ escrow_id: string; user_id: string; record: Parameters<typeof escrowRecordFromWire>[1]; capsule: CouncilCapsuleWire }>;
        }>(helper, 'GET', `/api/councils/reshare/${sessionId}/batch`)
      ).json;

      const verified = await verifyRosterChain(batch.chain.map((v) => signedVersionFromWire(COUNCIL, v)));
      expect(verified.ok).toBe(true);
      if (!verified.ok) return;

      const target = {
        sessionId,
        councilId: COUNCIL,
        target: verified.head,
        helperSlots: batch.helper_slots,
        mySlot: batch.my_slot,
        identitySecretKey: helper.identity.secretKey,
      };
      const { body: keys, transferKeys } = await buildReshareKeys({
        ...target,
        recipientKeys: await keysBySlot(batch.chain[batch.chain.length - 1], [alice, bruno, denis]),
      });
      expect((await call(helper, 'POST', `/api/councils/reshare/${sessionId}/keys`, keys, { signed: true })).status).toBe(200);

      const escrows = [];
      for (const entry of batch.escrows) {
        const share = await openCustodianShare(entry.capsule, escrowRecordFromWire(entry.user_id, entry.record), {
          userId: entry.user_id,
          councilId: COUNCIL,
          secretKeys: [helper.encryption.secretKey],
        });
        escrows.push(await buildReshareSubShares(target, transferKeys, entry.escrow_id, share));
      }

      expect((await call(helper, 'POST', `/api/councils/reshare/${sessionId}/sub-shares`, { escrows }, { signed: true })).status).toBe(200);
    }

    const escrow = await testPrisma.councilEscrow.findFirstOrThrow({ include: { capsules: true, rosterVersion: true } });
    expect(escrow.generation).toBe(2);
    expect(escrow.rosterVersion.version).toBe(2);
    expect(escrow.capsules.map((c) => c.slot).sort()).toEqual([1, 2, 4]);

    // Denis, who was never given anything by the user, now helps recover her.
    const ephemeral = await generateUserKeyPair();
    const ephemeralWire = base64ToUint8(exportPublicKeyAsBase64(ephemeral.publicKey));
    const { json } = await call<{ id: string }>(ursula, 'POST', '/api/council-recovery/requests', {
      ephemeral_public_key: uint8ToBase64(ephemeralWire),
    });
    expect((await contribute(alice, json.id, false)).json.stage).toBe('awaiting_meeting');
    expect((await contribute(denis, json.id, true)).json.stage).toBe('released');

    const released = (await call<Parameters<typeof recoverCouncilSecret>[0]>(ursula, 'GET', `/api/council-recovery/requests/${json.id}/shares`)).json;
    expect(
      (await recoverCouncilSecret(released, { publicKey: ephemeralWire, secretKey: ephemeral.secretKey }, wire(ursula.identity))).secret
    ).toEqual(secret);
  });

  it('refuses a helper whose commitments do not start from its own share, and moves nothing', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body } = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', body, { signed: true });

    configure([alice, bruno, denis], 2);
    await mine(denis);
    await signProposal(denis);
    await signProposal(alice);
    await signProposal(bruno);

    const sessionId = (
      await call<{ session_id: string }>(
        alice,
        'POST',
        `/api/councils/${COUNCIL}/reshare`,
        { source_version: 1, helper_slots: [1, 2] },
        { signed: true }
      )
    ).json.session_id;
    const batch = (
      await call<{ chain: RosterVersionWire[]; helper_slots: number[]; my_slot: number; escrows: Array<{ escrow_id: string }> }>(
        alice,
        'GET',
        `/api/councils/reshare/${sessionId}/batch`
      )
    ).json;
    const verified = await verifyRosterChain(batch.chain.map((v) => signedVersionFromWire(COUNCIL, v)));
    if (!verified.ok) throw new Error('chain refused');

    const target = {
      sessionId,
      councilId: COUNCIL,
      target: verified.head,
      helperSlots: batch.helper_slots,
      mySlot: batch.my_slot,
      identitySecretKey: alice.identity.secretKey,
    };
    const { body: keys, transferKeys } = await buildReshareKeys({
      ...target,
      recipientKeys: await keysBySlot(batch.chain[batch.chain.length - 1], [alice, bruno, denis]),
    });
    expect((await call(alice, 'POST', `/api/councils/reshare/${sessionId}/keys`, keys, { signed: true })).status).toBe(200);

    // Signed by Alice, but split from a value that is not her share.
    const wrong = encodeShare({ x: batch.my_slot, value: randomScalar(), blinding: randomScalar() });
    const entry = await buildReshareSubShares(target, transferKeys, batch.escrows[0].escrow_id, wrong);
    expect(
      (await call<{ code: string }>(alice, 'POST', `/api/councils/reshare/${sessionId}/sub-shares`, { escrows: [entry] }, { signed: true })).json
    ).toMatchObject({ code: API_ERROR_COUNCIL_RESHARE_INVALID });

    // Commitments signed by someone else are refused too.
    const resigned = await buildReshareSubShares(
      { ...target, identitySecretKey: bruno.identity.secretKey },
      transferKeys,
      batch.escrows[0].escrow_id,
      wrong
    );
    expect((await call(alice, 'POST', `/api/councils/reshare/${sessionId}/sub-shares`, { escrows: [resigned] }, { signed: true })).status).toBe(400);

    expect(await testPrisma.councilReshareCommitment.count()).toBe(0);
    expect((await testPrisma.councilEscrow.findFirstOrThrow()).generation).toBe(1);
  });

  it('refuses helpers that are not threshold custodians of the source still in the head', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    configure([alice, bruno, denis], 2);
    await mine(denis);
    await signProposal(denis);
    await signProposal(alice);
    await signProposal(bruno);

    expect(
      (await call(alice, 'POST', `/api/councils/${COUNCIL}/reshare`, { source_version: 1, helper_slots: [1, 3] }, { signed: true })).status
    ).toBe(400);
    expect((await call(alice, 'POST', `/api/councils/${COUNCIL}/reshare`, { source_version: 1, helper_slots: [1] }, { signed: true })).status).toBe(
      400
    );
    expect(
      (await call(alice, 'POST', `/api/councils/${COUNCIL}/reshare`, { source_version: 2, helper_slots: [1, 2] }, { signed: true })).status
    ).toBe(400);
  });
});
