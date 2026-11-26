import Fastify, { type FastifyInstance } from 'fastify';
import { randomBytes, randomUUID } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { rosterFingerprint, verifyRosterChain } from '@encryption/src/crypto/council';
import { signEscrow, signRoster } from '@encryption/src/crypto/council';
import { ephemeralKeyHash, requestFingerprint, verifyContribution, wrappedSharesHash } from '@encryption/src/crypto/council';
import {
  buildContribution,
  buildCouncilEscrow,
  buildReshareKeys,
  buildReshareSubShares,
  escrowRecordFromWire,
  openCustodianShare,
  recoverCouncilSecret,
  reshareTransferKeys,
  rosterRecordFromWire,
  signedVersionFromWire,
} from '@encryption/src/crypto/council-protocol';
import { type HybridKeyPair, ensureSodium, generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { base64ToUint8, exportPublicKeyAsBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { REQUEST_SIG_HEADER, signRequestProof } from '@encryption/src/crypto/request-proof';
import { SHAMIR_POINT_BYTES, encodeShare, randomScalar } from '@encryption/src/crypto/shamir';
import { type SignatureKeyPair, generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import { DEFAULT_KDF_PARAMS, signAuthPublicKeyBinding, signVaultChallenge } from '@encryption/src/crypto/vault-unlock';
import { testPrisma, useTestDatabase } from '@encryption/src/prisma/testing';
import { CouncilHeadChangedError, checkEscrowSubmission, writeEscrow } from '@encryption/src/server/council-escrow';
import { RELEASED_GRACE_MS, readyNoticeCandidates } from '@encryption/src/server/council-requests-core';
import { notifyReadyRequest, syncConfiguredCouncils, unconfiguredCouncilsWithEscrows } from '@encryption/src/server/council-sync';
import {
  sendCouncilHealthAlert,
  sendCouncilLeft,
  sendCouncilRecoveryMeeting,
  sendCouncilRecoveryReady,
  sendCouncilRecoveryRequested,
  sendCouncilRecoveryToApprove,
  sendCouncilRosterToSign,
} from '@encryption/src/server/email/council';
import { recoveryCouncilsSchema } from '@encryption/src/server/recovery-councils';
import { recoveryCouncilRoute } from '@encryption/src/server/routes/recovery-council';
import { vaultRoute } from '@encryption/src/server/routes/vault';
import {
  API_ERROR_COUNCIL_ALREADY_CONTRIBUTED,
  API_ERROR_COUNCIL_ENOUGH_SHARES,
  API_ERROR_COUNCIL_ESCROW_INVALID,
  API_ERROR_COUNCIL_ESCROW_UNRECOVERABLE,
  API_ERROR_COUNCIL_MEETING_FIRST,
  API_ERROR_COUNCIL_NOT_COVERED,
  API_ERROR_COUNCIL_NOT_CUSTODIAN,
  API_ERROR_COUNCIL_NOT_FOUND,
  API_ERROR_COUNCIL_NO_ESCROW,
  API_ERROR_COUNCIL_OWN_REQUEST,
  API_ERROR_COUNCIL_REARM_REQUIRED,
  API_ERROR_COUNCIL_REQUEST_CLOSED,
  API_ERROR_COUNCIL_REQUEST_EXISTS,
  API_ERROR_COUNCIL_REQUEST_NOT_FOUND,
  API_ERROR_COUNCIL_RESHARE_INVALID,
  API_ERROR_COUNCIL_RESHARE_KEYS_SENT,
  API_ERROR_COUNCIL_ROSTER_CHANGED,
  API_ERROR_COUNCIL_SIGNATURE_INVALID,
  API_ERROR_INSUFFICIENT_USER_AUTHENTICATION,
  API_ERROR_RATE_LIMIT_COUNCIL,
  API_ERROR_VAULT_KDF_PARAMS_INVALID,
} from '@encryption/src/shared/error-codes';
import type { CouncilCapsuleWire, CouncilCheckBatch, CouncilEscrowBody, RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';

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
  /** Stands in for the VRK a helper's transfer keys derive from. */
  vrk: Uint8Array;
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

  return { id, email, name, identity, encryption, vaultId: keyring.id, identityId: identityRow.id, vrk: new Uint8Array(randomBytes(32)) };
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
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
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

/** What the boot and the periodic sync do: turn the configuration into a proposal. */
async function sync() {
  await syncConfiguredCouncils(app.log);
}

async function configure(custodians: Person[], threshold: number) {
  env.RECOVERY_COUNCILS = recoveryCouncilsSchema.parse([
    {
      id: COUNCIL,
      label: 'Équipe sécurité DINUM',
      domains: ['numerique.gouv.fr'],
      custodians: custodians.map((c) => ({ userId: c.id, email: c.email })),
      threshold,
    },
  ]);
  await sync();
}

interface MineCouncil {
  council_id: string;
  label: string;
  role: string;
  configured: boolean;
  replaced_by: string | null;
  my_slot: number | null;
  chain: RosterVersionWire[];
  proposal: {
    roster: RosterVersionWire;
    quorum_missing: number;
    pending_members: Array<{ name: string }>;
    escrows_lost: number;
    may_sign: boolean;
  } | null;
  blocked: Array<{ email: string; name: string | null; member: boolean; reason: string }>;
  health: { escrows: number; ok: number; at_risk: number; lost: number; lost_names: string[]; outdated: Array<{ version: number; escrows: number }> };
  requests_count: number;
  requests_to_handle: number;
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

function versionsOf(chain: RosterVersionWire[]) {
  return chain.map((v) => rosterRecordFromWire(COUNCIL, v));
}

async function keysBySlot(roster: RosterVersionWire, people: Person[]) {
  return new Map(roster.members.map((m) => [m.slot, people.find((p) => p.id === m.user_id)!.encryption.publicKey]));
}

/** What the user's vault does to enroll: verify the chain, split a fresh secret, sign. */
async function enroll(
  user: Person,
  people: Person[],
  target?: { councilId: string; chain: RosterVersionWire[] }
): Promise<{ body: CouncilEscrowBody; secret: Uint8Array; auth: SignatureKeyPair }> {
  const wires = target?.chain ?? (await call<{ council: { chain: RosterVersionWire[] } }>(user, 'GET', '/api/councils/for-me')).json.council.chain;
  const chain = wires.map((v) => signedVersionFromWire(target?.councilId ?? COUNCIL, v));
  const verified = await verifyRosterChain(chain);
  if (!verified.ok) throw new Error(`chain refused: ${verified.reason}`);

  const head = wires[wires.length - 1];
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
      chain: RosterVersionWire[];
    }>(as, 'GET', `/api/council-recovery/requests/${requestId}/custodian`)
  ).json;

  const share = await openCustodianShare(detail.capsule, escrowRecordFromWire(detail.user_id, detail.escrow), {
    councilId: detail.council_id,
    versions: versionsOf(detail.chain),
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
let victor: Person; // another user

beforeEach(async () => {
  vi.clearAllMocks();
  app = buildApp();
  alice = await seedPerson(1, 'alice@numerique.gouv.fr', 'Alice Martin');
  bruno = await seedPerson(2, 'bruno@numerique.gouv.fr', 'Bruno Petit');
  chloe = await seedPerson(3, 'chloe@numerique.gouv.fr', 'Chloé Durand');
  denis = await seedPerson(4, 'denis@numerique.gouv.fr', 'Denis Moreau');
  ursula = await seedPerson(5, 'ursula@numerique.gouv.fr', 'Ursula Roux');
  victor = await seedPerson(6, 'victor@numerique.gouv.fr', 'Victor Leroy');
  env.OIDC_STEP_UP_ENABLED = false;
});

async function bootstrap(custodians: Person[], threshold: number) {
  await configure(custodians, threshold);
  for (const custodian of custodians) await signProposal(custodian);
}

describe('roster governance', () => {
  it('proposes the configured council, which takes effect once every custodian vouched for their own key', async () => {
    await configure([alice, bruno, chloe], 2);

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

  // A read never replaces a proposal nor emails: only the sync does, and it emails
  // a given roster once, however often the configuration flips back to it.
  it('proposes from the sync only, and emails a proposal once per content', async () => {
    env.RECOVERY_COUNCILS = recoveryCouncilsSchema.parse([
      {
        id: COUNCIL,
        label: 'DINUM',
        domains: ['numerique.gouv.fr'],
        custodians: [alice, bruno].map((c) => ({ userId: c.id, email: c.email })),
        threshold: 1,
      },
    ]);
    expect(await mine(alice)).toEqual([]);
    expect(sendCouncilRosterToSign).not.toHaveBeenCalled();

    await sync();
    expect(sendCouncilRosterToSign).toHaveBeenCalledTimes(2);

    await configure([alice, bruno, chloe], 2);
    expect(sendCouncilRosterToSign).toHaveBeenCalledTimes(5);

    env.RECOVERY_COUNCILS = recoveryCouncilsSchema.parse([
      {
        id: COUNCIL,
        label: 'DINUM',
        domains: ['numerique.gouv.fr'],
        custodians: [alice, bruno].map((c) => ({ userId: c.id, email: c.email })),
        threshold: 1,
      },
    ]);
    await sync();
    await sync();
    expect(sendCouncilRosterToSign).toHaveBeenCalledTimes(5);
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
    await sync();

    expect(await mine(alice)).toEqual([]);
    expect(await testPrisma.councilRosterVersion.count()).toBe(0);
  });

  it('replaces a custodian with k signatures of the previous version plus the newcomer, and deletes the leaver’s capsules', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body } = await enroll(ursula, [alice, bruno, chloe]);
    expect((await call(ursula, 'POST', '/api/councils/escrow', body, { signed: true })).status).toBe(200);

    await configure([alice, bruno, denis], 2);
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

  it('counts the escrows a change would make unrecoverable by keeping fewer current custodians than their threshold', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body } = await enroll(ursula, [alice, bruno, chloe]);
    expect((await call(ursula, 'POST', '/api/councils/escrow', body, { signed: true })).status).toBe(200);

    // Two of three kept: enough to move the escrow.
    await configure([alice, bruno, denis], 2);
    expect((await mine(alice))[0].proposal!.escrows_lost).toBe(0);

    // Only Alice kept: one share left of the two the escrow needs.
    await configure([alice, denis], 1);
    expect((await mine(alice))[0].proposal!.escrows_lost).toBe(1);
  });

  it('asks for a fresh authentication to confirm a membership', async () => {
    await configure([alice, bruno, chloe], 2);
    env.OIDC_STEP_UP_ENABLED = true;

    expect(await signProposal(alice)).toMatchObject({ status: 401 });
    env.OIDC_STEP_UP_ENABLED = false;
    expect(await signProposal(alice)).toMatchObject({ status: 200 });
  });

  it('refuses a signature over another roster than the one proposed', async () => {
    await configure([alice, bruno, chloe], 2);
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
    expect(council.health).toMatchObject({ escrows: 1, ok: 1, lost: 0, team_ready: true });

    const forMe = (await call<{ escrow: { health: { status: string } } }>(ursula, 'GET', '/api/councils/for-me')).json;
    expect(forMe.escrow.health.status).toBe('ok');
  });

  it('keeps a removed council under its name and its alerts while it protects someone, and closes it once it protects nobody', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body } = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', body, { signed: true });
    const configured = env.RECOVERY_COUNCILS;

    env.RECOVERY_COUNCILS = undefined;
    expect((await mine(alice))[0]).toMatchObject({ configured: false, label: 'Équipe sécurité DINUM' });

    // Its custodians still hear when it degrades.
    await testPrisma.identity.updateMany({ where: { userId: { in: [bruno.id, chloe.id] } }, data: { disabledAt: new Date() } });
    await sync();
    expect(await testPrisma.councilHealthNotice.findUnique({ where: { councilId: COUNCIL } })).toMatchObject({ status: 'lost' });
    expect(vi.mocked(sendCouncilHealthAlert).mock.calls.map(([p]) => p.council)).toEqual(['Équipe sécurité DINUM']);

    await testPrisma.councilEscrow.deleteMany({ where: { councilId: COUNCIL } });
    expect(await mine(alice)).toEqual([]);

    // Named again, it comes back with its chain.
    env.RECOVERY_COUNCILS = configured;
    expect((await mine(alice))[0]).toMatchObject({ configured: true, chain: [expect.anything()] });
  });

  it('asks for a new version when a custodian started over, and counts their shares as lost meanwhile', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body } = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', body, { signed: true });

    // Bruno starts over: a new identity with no continuity link.
    const fresh = await generateSignatureKeyPair();
    await testPrisma.identity.updateMany({ where: { userId: bruno.id }, data: { disabledAt: new Date() } });
    await testPrisma.identity.create({ data: { userId: bruno.id, generation: 2, signaturePublicKey: Buffer.from(wire(fresh)) } });
    await sync();

    const [council] = await mine(alice);
    // Bruno's former identity holds a slot of the head: nobody can join until the new version takes effect.
    expect(council.health).toMatchObject({ at_risk: 1, lost_names: [], team_ready: false });
    expect((await call<{ council: { team_ready: boolean } }>(ursula, 'GET', '/api/councils/for-me')).json.council.team_ready).toBe(false);
    expect(council.proposal?.roster.members.find((m) => m.user_id === bruno.id)?.slot).toBe(4);

    // Chloé too: one share left of two needed, and the team is told whom to warn.
    await testPrisma.identity.updateMany({ where: { userId: chloe.id }, data: { disabledAt: new Date() } });
    const [lost] = await mine(alice);
    expect(lost.health).toMatchObject({ lost: 1, lost_names: ['Ursula Roux'] });
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
    expect(await testPrisma.councilEscrow.count()).toBe(0);
  });

  // Each change below keeps the escrow signature valid, so only the check named refuses it.
  it('refuses a dormant credential that is not bound to the user, too cheap to guess, or commitments of another threshold', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body, auth } = await enroll(ursula, [alice, bruno, chloe]);

    const notBound = { ...body.credential, auth_pub_sig: uint8ToBase64(await signAuthPublicKeyBinding(auth.publicKey, victor.identity.secretKey)) };
    expect((await call(ursula, 'POST', '/api/councils/escrow', { ...body, credential: notBound }, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_ESCROW_INVALID,
    });

    const cheap = { ...body.credential, kdf_ops: DEFAULT_KDF_PARAMS.opsLimit - 1 };
    expect((await call(ursula, 'POST', '/api/councils/escrow', { ...body, credential: cheap }, { signed: true })).json).toMatchObject({
      code: API_ERROR_VAULT_KDF_PARAMS_INVALID,
    });

    const checked = await checkEscrowSubmission(ursula.id, body);
    if (!checked.ok) throw new Error(checked.code);
    const oneCommitment = checked.record.shareCommitments.slice(0, SHAMIR_POINT_BYTES);
    const resigned = {
      ...body,
      share_commitments: uint8ToBase64(oneCommitment),
      escrow_signature: uint8ToBase64(await signEscrow({ ...checked.record, shareCommitments: oneCommitment }, ursula.identity.secretKey)),
    };
    expect((await call(ursula, 'POST', '/api/councils/escrow', resigned, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_ESCROW_INVALID,
    });

    expect(await testPrisma.councilEscrow.count()).toBe(0);
  });

  it('checks an escrow against a council in force only, and writes nothing once a new version took effect', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body } = await enroll(ursula, [alice, bruno, chloe]);
    expect(await checkEscrowSubmission(ursula.id, { ...body, council_id: 'unknown' })).toMatchObject({
      ok: false,
      status: 404,
      code: API_ERROR_COUNCIL_NOT_FOUND,
    });

    const checked = await checkEscrowSubmission(ursula.id, body);
    if (!checked.ok) throw new Error(checked.code);

    await configure([alice, bruno, denis], 2);
    for (const custodian of [denis, alice, bruno]) await signProposal(custodian);

    await expect(testPrisma.$transaction((tx) => writeEscrow(tx, ursula.id, ursula.vaultId, body, checked))).rejects.toBeInstanceOf(
      CouncilHeadChangedError
    );
    expect(await testPrisma.councilEscrow.count()).toBe(0);
    expect(await testPrisma.vaultCredential.count({ where: { type: 'council' } })).toBe(0);
  });

  // An email change does not move an escrow: the user renews it with the council that holds it.
  it('keeps the user on the council their escrow names when their email leaves its domains', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const first = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', first.body, { signed: true });

    await testPrisma.user.update({ where: { id: ursula.id }, data: { email: 'ursula@example.org' } });

    const forMe = (await call<{ council: { council_id: string } | null; move_to: unknown }>(ursula, 'GET', '/api/councils/for-me')).json;
    expect(forMe).toMatchObject({ council: { council_id: COUNCIL }, move_to: null });
    const renewed = await enroll(ursula, [alice, bruno, chloe]);
    expect((await call(ursula, 'POST', '/api/councils/escrow', renewed.body, { signed: true })).status).toBe(200);
  });

  it('refuses an escrow for a council that does not cover the user', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const outsider = await seedPerson(7, 'olga@example.org', 'Olga Petrov');
    const { body } = await enroll(ursula, [alice, bruno, chloe]);

    expect((await call(outsider, 'POST', '/api/councils/escrow', body, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_NOT_COVERED,
    });
  });

  // The renewal after a custodian left: a fresh secret replaces the old one in
  // one write, so no share of the old secret opens anything any more.
  it('replaces the previous escrow, its credential and its capsules, unless a recovery is in progress', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const first = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', first.body, { signed: true });
    const before = await testPrisma.councilEscrow.findFirstOrThrow({ where: { userId: ursula.id } });

    const second = await enroll(ursula, [alice, bruno, chloe]);
    expect((await call(ursula, 'POST', '/api/councils/escrow', second.body, { signed: true })).status).toBe(200);

    const escrows = await testPrisma.councilEscrow.findMany({ where: { userId: ursula.id } });
    expect(escrows).toHaveLength(1);
    expect(escrows[0].id).not.toBe(before.id);
    expect(await testPrisma.vaultCredential.count({ where: { id: before.credentialId } })).toBe(0);
    expect(await testPrisma.councilCapsule.count({ where: { escrowId: before.id } })).toBe(0);

    await call(ursula, 'POST', '/api/council-recovery/requests', {
      ephemeral_public_key: exportPublicKeyAsBase64((await generateUserKeyPair()).publicKey),
    });
    const third = await enroll(ursula, [alice, bruno, chloe]);
    expect((await call(ursula, 'POST', '/api/councils/escrow', third.body, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_REQUEST_EXISTS,
    });
    expect((await testPrisma.councilEscrow.findFirstOrThrow({ where: { userId: ursula.id } })).id).toBe(escrows[0].id);
  });

  // A new council id (or a move to another domain): the council the user's email maps
  // to now is offered once in force, and joining it leaves the previous one.
  it('offers the council the email maps to now, and joining it leaves the previous one', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const first = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', first.body, { signed: true });
    const before = await testPrisma.councilEscrow.findFirstOrThrow({ where: { userId: ursula.id } });

    const NEXT = 'dinum-2027';
    env.RECOVERY_COUNCILS = recoveryCouncilsSchema.parse([
      {
        id: NEXT,
        label: 'Équipe sécurité DINUM 2027',
        domains: ['numerique.gouv.fr'],
        custodians: [alice, bruno, denis].map((c) => ({ userId: c.id, email: c.email })),
        threshold: 2,
      },
    ]);
    await sync();

    type ForMe = { escrow: { council_id: string } | null; move_to: { council_id: string; chain: RosterVersionWire[] } | null };
    // Not offered before the new council is in force.
    expect((await call<ForMe>(ursula, 'GET', '/api/councils/for-me')).json.move_to).toBeNull();

    for (const custodian of [alice, bruno, denis]) {
      const roster = (await mine(custodian)).find((c) => c.council_id === NEXT)!.proposal!.roster;
      const signature = await signRoster(rosterRecordFromWire(NEXT, roster), custodian.identity.secretKey);
      await call(
        custodian,
        'POST',
        `/api/councils/${NEXT}/versions/${roster.version}/sign`,
        { signature: uint8ToBase64(signature) },
        { signed: true }
      );
    }

    const forMe = (await call<ForMe>(ursula, 'GET', '/api/councils/for-me')).json;
    expect(forMe.escrow?.council_id).toBe(COUNCIL);
    expect(forMe.move_to?.council_id).toBe(NEXT);
    // Its custodians are told which team replaces it.
    const previous = (await mine(chloe)).find((c) => c.council_id === COUNCIL)!;
    expect(previous).toMatchObject({ configured: false, replaced_by: 'Équipe sécurité DINUM 2027' });

    const moved = await enroll(ursula, [alice, bruno, denis], { councilId: NEXT, chain: forMe.move_to!.chain });
    expect((await call(ursula, 'POST', '/api/councils/escrow', moved.body, { signed: true })).status).toBe(200);

    const escrows = await testPrisma.councilEscrow.findMany({ where: { userId: ursula.id } });
    expect(escrows.map((e) => e.councilId)).toEqual([NEXT]);
    expect(await testPrisma.vaultCredential.count({ where: { id: before.credentialId } })).toBe(0);
    expect((await call<ForMe>(ursula, 'GET', '/api/councils/for-me')).json.move_to).toBeNull();

    // Protecting nobody now, the previous council is closed: gone from its custodians' space.
    expect((await mine(chloe)).find((c) => c.council_id === COUNCIL)).toBeUndefined();

    // And it no longer covers them.
    const back = await enroll(ursula, [alice, bruno, chloe], { councilId: COUNCIL, chain: previous.chain });
    expect((await call(ursula, 'POST', '/api/councils/escrow', back.body, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_NOT_COVERED,
    });
  });

  it('leaves an older vault with the council the user moves away from, which only it can give back', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const older = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', older.body, { signed: true });

    // Ursula starts over: a new identity and vault, joined to the same council.
    await testPrisma.identity.updateMany({ where: { userId: ursula.id }, data: { disabledAt: new Date() } });
    await testPrisma.vaultKeyring.updateMany({ where: { userId: ursula.id }, data: { disabledAt: new Date() } });
    const identity = await generateSignatureKeyPair();
    const identityRow = await testPrisma.identity.create({
      data: { userId: ursula.id, generation: 2, signaturePublicKey: Buffer.from(wire(identity)) },
    });
    const keyring = await testPrisma.vaultKeyring.create({ data: { userId: ursula.id, identityId: identityRow.id } });
    ursula = { ...ursula, identity, identityId: identityRow.id, vaultId: keyring.id };
    const current = await enroll(ursula, [alice, bruno, chloe]);
    expect((await call(ursula, 'POST', '/api/councils/escrow', current.body, { signed: true })).status).toBe(200);
    expect(await testPrisma.councilEscrow.count({ where: { userId: ursula.id } })).toBe(2);

    const NEXT = 'dinum-2027';
    env.RECOVERY_COUNCILS = recoveryCouncilsSchema.parse([
      {
        id: NEXT,
        label: 'Équipe sécurité DINUM 2027',
        domains: ['numerique.gouv.fr'],
        custodians: [alice, bruno, denis].map((c) => ({ userId: c.id, email: c.email })),
        threshold: 2,
      },
    ]);
    await sync();
    for (const custodian of [alice, bruno, denis]) {
      const roster = (await mine(custodian)).find((c) => c.council_id === NEXT)!.proposal!.roster;
      const signature = await signRoster(rosterRecordFromWire(NEXT, roster), custodian.identity.secretKey);
      await call(
        custodian,
        'POST',
        `/api/councils/${NEXT}/versions/${roster.version}/sign`,
        { signature: uint8ToBase64(signature) },
        { signed: true }
      );
    }

    type ForMe = {
      move_to: { council_id: string; chain: RosterVersionWire[] } | null;
      vaults: Array<{ council_label: string; active: boolean }>;
    };
    const forMe = (await call<ForMe>(ursula, 'GET', '/api/councils/for-me')).json;
    const moved = await enroll(ursula, [alice, bruno, denis], { councilId: NEXT, chain: forMe.move_to!.chain });
    expect((await call(ursula, 'POST', '/api/councils/escrow', moved.body, { signed: true })).status).toBe(200);

    const escrows = await testPrisma.councilEscrow.findMany({ where: { userId: ursula.id }, include: { credential: true } });
    expect(escrows.map((e) => [e.councilId, e.credential.vaultId === keyring.id]).sort()).toEqual([
      [COUNCIL, false],
      [NEXT, true],
    ]);

    // The council left keeps protecting that vault, so its custodians still see it, and the user can ask it back.
    expect((await mine(chloe)).find((c) => c.council_id === COUNCIL)?.health.escrows).toBe(1);
    const after = (await call<ForMe>(ursula, 'GET', '/api/councils/for-me')).json;
    expect(after.vaults).toEqual([
      expect.objectContaining({ council_label: 'Équipe sécurité DINUM 2027', active: true }),
      expect.objectContaining({ council_label: 'Équipe sécurité DINUM', active: false }),
    ]);
    expect(after.move_to).toBeNull();
  });

  it('lets the user leave, signed, outside a recovery, and join again', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const first = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', first.body, { signed: true });
    const escrow = await testPrisma.councilEscrow.findFirstOrThrow({ where: { userId: ursula.id } });

    // A login alone cannot take the user out.
    expect((await call(ursula, 'DELETE', '/api/councils/escrow')).status).toBe(401);

    await call(ursula, 'POST', '/api/council-recovery/requests', {
      ephemeral_public_key: exportPublicKeyAsBase64((await generateUserKeyPair()).publicKey),
    });
    expect((await call(ursula, 'DELETE', '/api/councils/escrow', undefined, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_REQUEST_EXISTS,
    });
    const { request } = (await call<{ request: { id: string } }>(ursula, 'GET', '/api/council-recovery/requests/mine')).json;
    await call(ursula, 'POST', `/api/council-recovery/requests/${request.id}/refuse`);

    // Signed is not enough: it takes a fresh second factor too.
    env.OIDC_STEP_UP_ENABLED = true;
    expect((await call(ursula, 'DELETE', '/api/councils/escrow', undefined, { signed: true })).json).toMatchObject({
      code: API_ERROR_INSUFFICIENT_USER_AUTHENTICATION,
    });
    env.OIDC_STEP_UP_ENABLED = false;
    expect(sendCouncilLeft).not.toHaveBeenCalled();

    expect((await call(ursula, 'DELETE', '/api/councils/escrow', undefined, { signed: true })).json).toEqual({ left: 1 });
    // Told by email, in case it was not them.
    expect(sendCouncilLeft).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ recipient: 'ursula@numerique.gouv.fr' }));
    expect(await testPrisma.councilEscrow.count({ where: { userId: ursula.id } })).toBe(0);
    expect(await testPrisma.vaultCredential.count({ where: { id: escrow.credentialId } })).toBe(0);
    expect(await testPrisma.councilCapsule.count({ where: { escrowId: escrow.id } })).toBe(0);

    const again = await enroll(ursula, [alice, bruno, chloe]);
    expect((await call(ursula, 'POST', '/api/councils/escrow', again.body, { signed: true })).status).toBe(200);
  });

  // A council is its id: a rename starts a new one and leaves the users on the old.
  it('names a council that still holds escrows once it left the configuration', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body } = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', body, { signed: true });
    expect(await unconfiguredCouncilsWithEscrows()).toEqual([]);

    env.RECOVERY_COUNCILS = recoveryCouncilsSchema.parse([
      {
        id: 'dinum-renamed',
        label: 'Équipe sécurité DINUM',
        domains: ['numerique.gouv.fr'],
        custodians: [alice, bruno, chloe].map((c) => ({ userId: c.id, email: c.email })),
        threshold: 2,
      },
    ]);
    expect(await unconfiguredCouncilsWithEscrows()).toEqual([{ councilId: COUNCIL, escrows: 1 }]);
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

  // Turned off since: custodians and user alike check the escrow under the identity its vault was created under.
  it('gives back an earlier vault, naming the identity it was created under', async () => {
    const { secret, auth } = await enrolled();
    await testPrisma.identity.updateMany({ where: { userId: ursula.id }, data: { disabledAt: new Date() } });
    await testPrisma.vaultKeyring.updateMany({ where: { userId: ursula.id }, data: { disabledAt: new Date() } });
    const { id, ephemeral } = await ask();
    const earlier = uint8ToBase64(wire(ursula.identity));

    const detail = (await call<{ owner_identity_public_key: string }>(alice, 'GET', `/api/council-recovery/requests/${id}/custodian`)).json;
    expect(detail.owner_identity_public_key).toBe(earlier);
    await contribute(bruno, id, true);
    expect((await contribute(alice, id, false)).json.stage).toBe('released');

    const released = (await call<Parameters<typeof recoverCouncilSecret>[0]>(ursula, 'GET', `/api/council-recovery/requests/${id}/shares`)).json;
    expect(released.owner_identity_public_key).toBe(earlier);
    expect((await recoverCouncilSecret(released, ephemeral, base64ToUint8(released.owner_identity_public_key))).secret).toEqual(secret);

    // Bringing the vault back and the new phrase are one write, gated by the released phrase.
    const proven = async () => {
      const challenge = (await call<{ challenge_id: string; nonce: string }>(ursula, 'POST', '/api/vault/challenge')).json;
      const proof = await signVaultChallenge(base64ToUint8(challenge.nonce), ursula.id, auth.secretKey);

      return { challenge_id: challenge.challenge_id, proof: uint8ToBase64(proof) };
    };
    const newAuth = await generateSignatureKeyPair();
    const keyring = {
      wrapped_vrk: uint8ToBase64(new Uint8Array(randomBytes(72))),
      auth_public_key: uint8ToBase64(newAuth.publicKey),
      auth_pub_sig: uint8ToBase64(await signAuthPublicKeyBinding(newAuth.publicKey, ursula.identity.secretKey)),
      kdf_ops: DEFAULT_KDF_PARAMS.opsLimit,
      kdf_mem: DEFAULT_KDF_PARAMS.memLimit,
      lang: 'english',
    };
    const retired = async () => (await testPrisma.vaultKeyring.findFirstOrThrow({ where: { userId: ursula.id } })).disabledAt !== null;

    // A refused write leaves everything as it was: still retired, still released.
    expect((await call(ursula, 'POST', '/api/vault/reactivate-keyring', { ...(await proven()), keyring })).json).toMatchObject({
      code: API_ERROR_COUNCIL_REARM_REQUIRED,
    });
    expect(await retired()).toBe(true);
    expect(await testPrisma.councilRequest.count({ where: { status: 'released' } })).toBe(1);

    const rearm = await enroll(ursula, [alice, bruno, chloe]);
    const res = await call(ursula, 'POST', '/api/vault/reactivate-keyring', {
      ...(await proven()),
      keyring: { ...keyring, council_rearm: rearm.body },
    });
    expect(res.status).toBe(200);
    expect(await retired()).toBe(false);
    expect(await testPrisma.identity.count({ where: { userId: ursula.id, disabledAt: null } })).toBe(1);
    expect(await testPrisma.councilRequest.count({ where: { status: 'completed' } })).toBe(1);
    expect(await testPrisma.councilEscrow.count()).toBe(1);
  });

  it('gives the vault back after a meeting, then remote approvals', async () => {
    const { secret, auth } = await enrolled();
    const { id, ephemeral } = await ask();
    expect(sendCouncilRecoveryRequested).toHaveBeenCalledOnce();
    // The meeting comes first: the user is told who to see, each custodian that one of them must meet her.
    expect(sendCouncilRecoveryMeeting).toHaveBeenCalledWith(expect.objectContaining({ custodians: 'Alice Martin, Bruno Petit, Chloé Durand' }));
    expect(vi.mocked(sendCouncilRecoveryToApprove).mock.calls.map(([p]) => p.step)).toEqual(['meet', 'meet', 'meet']);

    expect((await call(ursula, 'GET', '/api/council-recovery/requests/mine')).json).toMatchObject({
      request: { stage: 'meet', meet: [{ name: 'Alice Martin' }, { name: 'Bruno Petit' }, { name: 'Chloé Durand' }] },
    });

    // No remote approval before the meeting: nobody has checked the key yet.
    expect((await contribute(alice, id, false)).json).toMatchObject({ code: API_ERROR_COUNCIL_MEETING_FIRST });
    const before = (await call<{ attestation: unknown; meeting_required: boolean }>(alice, 'GET', `/api/council-recovery/requests/${id}/custodian`))
      .json;
    expect(before).toMatchObject({ attestation: null, meeting_required: true });

    vi.mocked(sendCouncilRecoveryToApprove).mockClear();
    expect((await contribute(bruno, id, true)).json.stage).toBe('collecting');
    // The others may now approve remotely, and are told so.
    expect(vi.mocked(sendCouncilRecoveryToApprove).mock.calls.map(([p]) => [p.recipient, p.step])).toEqual([
      ['alice@numerique.gouv.fr', 'approve'],
      ['chloe@numerique.gouv.fr', 'approve'],
    ]);
    expect((await call(ursula, 'GET', '/api/council-recovery/requests/mine')).json).toMatchObject({ request: { stage: 'in_progress', meet: [] } });

    // What Alice's vault checks before releasing anything: Bruno's signed in-person share for this very key.
    const after = (
      await call<{ attestation: { slot: number; custodian_user_id: string; wrapped_share: string; signature: string }; meeting_required: boolean }>(
        alice,
        'GET',
        `/api/council-recovery/requests/${id}/custodian`
      )
    ).json;
    expect(after.meeting_required).toBe(false);
    expect(after.attestation).toMatchObject({ slot: 2, custodian_user_id: bruno.id });
    expect(
      await verifyContribution(
        {
          requestId: id,
          userId: ursula.id,
          councilId: COUNCIL,
          slot: 2,
          custodianUserId: bruno.id,
          ephemeralPublicKeyHash: await ephemeralKeyHash(ephemeral.publicKey),
          wrappedSharesHash: await wrappedSharesHash([base64ToUint8(after.attestation.wrapped_share)]),
          inPerson: true,
        },
        base64ToUint8(after.attestation.signature),
        wire(bruno.identity)
      )
    ).toBe(true);

    expect((await contribute(alice, id, false)).json.stage).toBe('released');
    // Sent back to the browser that asked, once.
    expect(sendCouncilRecoveryReady).toHaveBeenCalledTimes(1);
    expect(sendCouncilRecoveryReady).toHaveBeenCalledWith(expect.objectContaining({ recipient: ursula.email }));

    const released = (await call<Parameters<typeof recoverCouncilSecret>[0]>(ursula, 'GET', `/api/council-recovery/requests/${id}/shares`)).json;
    const recovered = await recoverCouncilSecret(released, ephemeral, wire(ursula.identity));
    expect(recovered.secret).toEqual(secret);
    expect(recovered.contributors.map((c) => c.inPerson).sort()).toEqual([false, true]);

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

    // The request outlives the burned escrow, completed and without its shares: it still counts towards the limit on asking.
    expect(await testPrisma.councilRequest.findUniqueOrThrow({ where: { id } })).toMatchObject({ status: 'completed', escrowId: null });
    expect(await testPrisma.councilContribution.count({ where: { requestId: id } })).toBe(0);
    expect((await call(ursula, 'GET', '/api/council-recovery/requests/mine')).json).toEqual({ request: null, ended: null });
    const escrows = await testPrisma.councilEscrow.findMany();
    expect(escrows).toHaveLength(1);
    expect(new Uint8Array(escrows[0].secretCommitment)).toEqual(base64ToUint8(rearm.body.secret_commitment));
  });

  it('lets the phrase change leave the council when its setup cannot be renewed', async () => {
    await enrolled();
    const { id } = await ask();
    await contribute(bruno, id, true);
    await contribute(alice, id, false);

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
    expect((await contribute(bruno, id, true)).json.stage).toBe('collecting');
    expect((await call(alice, 'POST', `/api/council-recovery/requests/${id}/contribute`, forged, { signed: true })).json).toMatchObject({
      stage: 'released',
    });

    const released = (await call<Parameters<typeof recoverCouncilSecret>[0]>(ursula, 'GET', `/api/council-recovery/requests/${id}/shares`)).json;
    await expect(recoverCouncilSecret(released, ephemeral, wire(ursula.identity))).rejects.toThrow('Not enough valid shares');
  });

  it('accepts no remote approval before the meeting, and k - 1 of them after it', async () => {
    await bootstrap([alice, bruno, chloe, denis], 3);
    const enrollment = await enroll(ursula, [alice, bruno, chloe, denis]);
    await call(ursula, 'POST', '/api/councils/escrow', enrollment.body, { signed: true });
    const { id } = await ask();

    for (const custodian of [alice, bruno, chloe]) {
      expect((await contribute(custodian, id, false)).json).toMatchObject({ code: API_ERROR_COUNCIL_MEETING_FIRST });
    }
    expect(await testPrisma.councilContribution.count()).toBe(0);

    expect((await contribute(denis, id, true)).json.stage).toBe('collecting');
    expect((await contribute(alice, id, false)).json.stage).toBe('collecting');
    expect((await call(ursula, 'GET', `/api/council-recovery/requests/${id}/shares`)).status).toBe(400);
    expect((await contribute(bruno, id, false)).json.stage).toBe('released');
    // Released at k: a fourth share is not needed and not taken.
    expect((await call(chloe, 'GET', `/api/council-recovery/requests/${id}/custodian`)).json).toMatchObject({
      code: API_ERROR_COUNCIL_REQUEST_CLOSED,
    });
  });

  it('releases on the meeting alone with a threshold of 1', async () => {
    await bootstrap([alice, bruno], 1);
    const enrollment = await enroll(ursula, [alice, bruno]);
    await call(ursula, 'POST', '/api/councils/escrow', enrollment.body, { signed: true });
    const { id, ephemeral } = await ask();

    expect((await contribute(alice, id, false)).json).toMatchObject({ code: API_ERROR_COUNCIL_MEETING_FIRST });
    expect((await contribute(bruno, id, true)).json.stage).toBe('released');

    const released = (await call<Parameters<typeof recoverCouncilSecret>[0]>(ursula, 'GET', `/api/council-recovery/requests/${id}/shares`)).json;
    expect((await recoverCouncilSecret(released, ephemeral, wire(ursula.identity))).secret).toEqual(enrollment.secret);
  });

  it('keeps one request at a time, and lets the user refuse it', async () => {
    await enrolled();
    const { id } = await ask();

    expect(
      (await call(ursula, 'POST', '/api/council-recovery/requests', { ephemeral_public_key: uint8ToBase64(new Uint8Array(33)) })).json
    ).toMatchObject({
      code: API_ERROR_COUNCIL_REQUEST_EXISTS,
    });

    await contribute(alice, id, true);
    expect((await call(ursula, 'POST', `/api/council-recovery/requests/${id}/refuse`)).status).toBe(200);
    expect(await testPrisma.councilContribution.count()).toBe(0);
    expect((await call(ursula, 'GET', '/api/council-recovery/requests/mine')).json).toEqual({ request: null, ended: null });
  });

  // A user who started over, then wants back what came before: the council holds
  // both vaults, and the request names the one to give back.
  it('lists every vault the council can give back, and asks for the one named', async () => {
    await enrolled();
    const older = await testPrisma.councilEscrow.findFirstOrThrow({ where: { userId: ursula.id } });
    await testPrisma.vaultKeyring.update({ where: { id: ursula.vaultId }, data: { disabledAt: new Date(Date.UTC(2026, 5, 1)) } });
    await testPrisma.vaultKeyring.create({ data: { userId: ursula.id, identityId: ursula.identityId } });
    await call(ursula, 'POST', '/api/councils/escrow', (await enroll(ursula, [alice, bruno, chloe])).body, { signed: true });

    const { vaults } = (
      await call<{ vaults: Array<{ escrow_id: string; active: boolean; disabled_at_millis: number | null }> }>(ursula, 'GET', '/api/councils/for-me')
    ).json;
    expect(vaults.map((v) => [v.active, v.disabled_at_millis])).toEqual([
      [true, null],
      [false, Date.UTC(2026, 5, 1)],
    ]);
    expect(vaults[1].escrow_id).toBe(older.id);

    const res = await call<{ id: string }>(ursula, 'POST', '/api/council-recovery/requests', {
      ephemeral_public_key: uint8ToBase64(new Uint8Array(33)),
      escrow_id: older.id,
    });
    expect(res.status).toBe(200);
    expect((await testPrisma.councilRequest.findUniqueOrThrow({ where: { id: res.json.id } })).escrowId).toBe(older.id);

    // Someone else's escrow is not one of the user's vaults.
    await testPrisma.councilRequest.deleteMany();
    const other = await call(victor, 'POST', '/api/council-recovery/requests', {
      ephemeral_public_key: uint8ToBase64(new Uint8Array(33)),
      escrow_id: older.id,
    });
    expect(other.json).toMatchObject({ code: API_ERROR_COUNCIL_NO_ESCROW });
  });

  // Back in with their own phrase before the council finished: the request has
  // no purpose left and closes, while one for an older vault would stay.
  it('closes the request when the user opens that vault with their own phrase', async () => {
    await enrolled();
    const { id } = await ask();
    await contribute(alice, id, true);

    const auth = await generateSignatureKeyPair();
    await testPrisma.vaultCredential.updateMany({
      where: { vaultId: ursula.vaultId, type: 'primary' },
      data: { authPublicKey: Buffer.from(auth.publicKey) },
    });
    const { json: challenge } = await call<{ challenge_id: string; nonce: string }>(ursula, 'POST', '/api/vault/challenge');
    const proof = await signVaultChallenge(base64ToUint8(challenge.nonce), ursula.id, auth.secretKey);
    const fetched = await call<{ council_request_closed: boolean }>(ursula, 'POST', '/api/vault/fetch', {
      challenge_id: challenge.challenge_id,
      proof: uint8ToBase64(proof),
    });

    expect(fetched).toMatchObject({ status: 200, json: { council_request_closed: true } });
    expect(await testPrisma.councilRequest.findUniqueOrThrow({ where: { id } })).toMatchObject({ status: 'refused' });
    expect(await testPrisma.councilContribution.count()).toBe(0);
    expect((await call(ursula, 'GET', '/api/council-recovery/requests/mine')).json).toEqual({ request: null, ended: null });
  });

  // Opening the vault in use says nothing about an older one the user asked for:
  // that request stays, and its answer will offer the choice.
  it('keeps a request for an older vault when the user opens the one in use', async () => {
    await enrolled();
    const older = await testPrisma.councilEscrow.findFirstOrThrow({ where: { userId: ursula.id } });
    await testPrisma.vaultKeyring.update({ where: { id: ursula.vaultId }, data: { disabledAt: new Date() } });
    const current = await testPrisma.vaultKeyring.create({ data: { userId: ursula.id, identityId: ursula.identityId } });
    const auth = await generateSignatureKeyPair();
    await testPrisma.vaultCredential.create({
      data: {
        vaultId: current.id,
        type: 'primary',
        wrappedVrk: 'WRAPPED',
        authPublicKey: Buffer.from(auth.publicKey),
        authPubSig: Buffer.from(randomBytes(64)),
        kdfOps: DEFAULT_KDF_PARAMS.opsLimit,
        kdfMem: DEFAULT_KDF_PARAMS.memLimit,
        lang: 'english',
      },
    });
    const { id } = (
      await call<{ id: string }>(ursula, 'POST', '/api/council-recovery/requests', {
        ephemeral_public_key: uint8ToBase64(new Uint8Array(33)),
        escrow_id: older.id,
      })
    ).json;

    const { json: challenge } = await call<{ challenge_id: string; nonce: string }>(ursula, 'POST', '/api/vault/challenge');
    const proof = await signVaultChallenge(base64ToUint8(challenge.nonce), ursula.id, auth.secretKey);
    const fetched = await call(ursula, 'POST', '/api/vault/fetch', { challenge_id: challenge.challenge_id, proof: uint8ToBase64(proof) });

    expect(fetched).toMatchObject({ status: 200, json: { council_request_closed: false } });
    expect(await testPrisma.councilRequest.findUniqueOrThrow({ where: { id } })).toMatchObject({ status: 'open' });
  });

  // The custodian space pages, filters and searches on the server: a council
  // with many requests never sends them all.
  it('lists a council’s requests one page at a time, filtered and searched', async () => {
    await enrolled();
    await call(victor, 'POST', '/api/councils/escrow', (await enroll(victor, [alice, bruno, chloe])).body, { signed: true });
    const { id: ursulaRequest } = await ask();
    await call(victor, 'POST', '/api/council-recovery/requests', { ephemeral_public_key: uint8ToBase64(new Uint8Array(33)) });
    await contribute(alice, ursulaRequest, true);

    type Page = {
      items: Array<{ id: string; user_email: string; can_contribute: boolean; created_at_millis: number }>;
      total_count: number;
      counts: Record<string, number>;
    };
    const list = async (as: Person, query: string) => call<Page>(as, 'GET', `/api/councils/${COUNCIL}/requests?${query}`);

    // Alice met Ursula already: only Victor's request waits on her, so it comes first.
    const all = (await list(alice, '')).json;
    expect(all.items.map((r) => r.user_email)).toEqual(['victor@numerique.gouv.fr', 'ursula@numerique.gouv.fr']);
    expect(all.total_count).toBe(2);
    expect(all.counts).toMatchObject({ all: 2, 'to-handle': 1, awaiting_meeting: 1, collecting: 1 });
    expect((await mine(alice))[0]).toMatchObject({ requests_count: 2, requests_to_handle: 1 });

    expect((await list(alice, 'filter=collecting')).json.items.map((r) => r.id)).toEqual([ursulaRequest]);
    expect((await list(alice, 'query=ROUX')).json).toMatchObject({ total_count: 1, items: [{ id: ursulaRequest }] });
    expect((await list(alice, 'page=2&page_size=5')).json).toMatchObject({ items: [], total_count: 2 });
    // A search is literal, wildcards included; one open for days has stalled.
    expect((await list(alice, 'query=%25')).json).toMatchObject({ total_count: 0 });
    await testPrisma.councilRequest.update({ where: { id: ursulaRequest }, data: { createdAt: new Date(Date.now() - 4 * 86_400_000) } });
    expect((await list(alice, 'filter=stalled')).json).toMatchObject({ total_count: 1, items: [{ id: ursulaRequest }], counts: { stalled: 1 } });
    // Dates come back as they were stored.
    const stored = await testPrisma.councilRequest.findUniqueOrThrow({ where: { id: ursulaRequest } });
    expect((await list(alice, 'filter=stalled')).json.items[0]).toMatchObject({ created_at_millis: stored.createdAt.getTime() });

    expect((await list(alice, 'page_size=7')).status).toBe(400);
    expect((await list(victor, '')).status).toBe(404);
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
    // The browser that asked is told why its request is gone.
    expect((await call(ursula, 'GET', '/api/council-recovery/requests/mine')).json).toMatchObject({
      request: null,
      ended: { reason: 'aborted', council_label: expect.any(String), ephemeral_fingerprint: expect.any(String) },
    });
  });

  // Reading the shares and refusing skip the request signature: only the request's own user may do either.
  it('shows and lets refuse a request to its user only', async () => {
    await enrolled();
    const { id } = await ask();
    const notFound = { code: API_ERROR_COUNCIL_REQUEST_NOT_FOUND };

    expect((await call(victor, 'GET', `/api/council-recovery/requests/${id}/shares`)).json).toMatchObject(notFound);
    expect((await call(victor, 'POST', `/api/council-recovery/requests/${id}/refuse`)).json).toMatchObject(notFound);
    expect((await call(alice, 'POST', `/api/council-recovery/requests/${id}/refuse`)).json).toMatchObject(notFound);
    expect((await call(alice, 'GET', `/api/council-recovery/requests/${randomUUID()}/custodian`)).json).toMatchObject(notFound);

    expect((await call<{ request: { id: string } | null }>(ursula, 'GET', '/api/council-recovery/requests/mine')).json.request?.id).toBe(id);
  });

  it('refuses a share signed by another custodian than the one sending it', async () => {
    await enrolled();
    const { id } = await ask();
    const detail = (await call<{ user_id: string; ephemeral_public_key: string }>(alice, 'GET', `/api/council-recovery/requests/${id}/custodian`))
      .json;

    const signedByBruno = await buildContribution({
      requestId: id,
      userId: detail.user_id,
      councilId: COUNCIL,
      slot: 1,
      custodianUserId: alice.id,
      ephemeralPublicKey: base64ToUint8(detail.ephemeral_public_key),
      encodedShare: encodeShare({ x: 1, value: randomScalar(), blinding: randomScalar() }),
      inPerson: true,
      identitySecretKey: bruno.identity.secretKey,
    });
    expect((await call(alice, 'POST', `/api/council-recovery/requests/${id}/contribute`, signedByBruno, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_SIGNATURE_INVALID,
    });
    expect(await testPrisma.councilContribution.count()).toBe(0);
  });

  it('takes one share per custodian and request', async () => {
    await enrolled();
    const { id } = await ask();

    expect((await contribute(alice, id, true)).json.stage).toBe('collecting');
    expect((await contribute(alice, id, true)).json).toMatchObject({ code: API_ERROR_COUNCIL_ALREADY_CONTRIBUTED });
    expect(await testPrisma.councilContribution.count({ where: { requestId: id } })).toBe(1);
  });

  it('refuses a request that fewer custodians than the threshold could still answer', async () => {
    await enrolled();
    await testPrisma.identity.updateMany({ where: { userId: { in: [bruno.id, chloe.id] } }, data: { disabledAt: new Date() } });

    const res = await call(ursula, 'POST', '/api/council-recovery/requests', {
      ephemeral_public_key: exportPublicKeyAsBase64((await generateUserKeyPair()).publicKey),
    });
    expect(res).toMatchObject({ status: 409, json: { code: API_ERROR_COUNCIL_ESCROW_UNRECOVERABLE } });
    expect(await testPrisma.councilRequest.count()).toBe(0);
  });

  it('tells the user which key the request waits for, so a browser can recognize its own', async () => {
    await enrolled();
    const { ephemeral } = await ask();

    const mineRes = (await call<{ request: { ephemeral_fingerprint: string } }>(ursula, 'GET', '/api/council-recovery/requests/mine')).json;
    expect(mineRes.request.ephemeral_fingerprint).toBe(await requestFingerprint(ephemeral.publicKey));
  });

  it('refuses a share after the request was refused, and a custodian’s share to their own request', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body } = await enroll(alice, [alice, bruno, chloe]);
    await call(alice, 'POST', '/api/councils/escrow', body, { signed: true });

    const ephemeral = await generateUserKeyPair();
    const { json } = await call<{ id: string }>(alice, 'POST', '/api/council-recovery/requests', {
      ephemeral_public_key: exportPublicKeyAsBase64(ephemeral.publicKey),
    });
    expect((await call(alice, 'GET', `/api/council-recovery/requests/${json.id}/custodian`)).json).toMatchObject({
      code: API_ERROR_COUNCIL_OWN_REQUEST,
    });

    const detailed = await contribute(bruno, json.id, true);
    expect(detailed.json.stage).toBe('collecting');
    await call(alice, 'POST', `/api/council-recovery/requests/${json.id}/refuse`);
    expect(await testPrisma.councilContribution.count()).toBe(0);
    expect((await call(chloe, 'GET', `/api/council-recovery/requests/${json.id}/custodian`)).json).toMatchObject({
      code: API_ERROR_COUNCIL_REQUEST_CLOSED,
    });
  });

  it('keeps the cooldown a request was created with', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const config = (env.RECOVERY_COUNCILS as Array<{ cooldownMinutes: number }>)[0];
    config.cooldownMinutes = 60;
    const enrollment = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', enrollment.body, { signed: true });
    const { id } = await ask();

    config.cooldownMinutes = 0;
    await contribute(bruno, id, true);
    const timers = vi.spyOn(globalThis, 'setTimeout');
    expect((await contribute(alice, id, false)).json.stage).toBe('cooldown');
    const notice = timers.mock.calls.find(([, delay]) => typeof delay === 'number' && delay > 59 * 60_000 && delay <= 60 * 60_000);
    timers.mockRestore();
    expect(notice).toBeDefined();
    expect(sendCouncilRecoveryReady).not.toHaveBeenCalled();

    // At the end of the cooldown the timer tells the user; the hourly run behind it does not tell them again.
    await testPrisma.councilRequest.update({ where: { id }, data: { releaseNotBefore: new Date(Date.now() - 1000) } });
    (notice![0] as () => void)();
    await vi.waitFor(() => expect(sendCouncilRecoveryReady).toHaveBeenCalledTimes(1));
    for (const requestId of await readyNoticeCandidates()) await notifyReadyRequest(requestId, app.log);
    expect(sendCouncilRecoveryReady).toHaveBeenCalledTimes(1);
  });

  // Released in its last hours, a request would expire before the user changes the phrase they got back.
  it('leaves the user at least two days once the shares are released', async () => {
    await enrolled();
    const { id } = await ask();
    const original = (await testPrisma.councilRequest.findUniqueOrThrow({ where: { id } })).expiresAt.getTime();
    await contribute(bruno, id, true);
    await testPrisma.councilRequest.update({ where: { id }, data: { expiresAt: new Date(Date.now() + 60 * 60 * 1000) } });

    const before = Date.now();
    expect((await contribute(alice, id, false)).json.stage).toBe('released');
    const late = await testPrisma.councilRequest.findUniqueOrThrow({ where: { id } });
    expect(late.expiresAt.getTime()).toBeGreaterThanOrEqual(before + RELEASED_GRACE_MS);

    // With time left, the request keeps the expiry it was asked with.
    await testPrisma.councilRequest.update({ where: { id }, data: { status: 'completed', closedAt: new Date() } });
    const again = await ask();
    await contribute(bruno, again.id, true);
    await contribute(alice, again.id, false);
    const kept = await testPrisma.councilRequest.findUniqueOrThrow({ where: { id: again.id } });
    expect(kept.status).toBe('released');
    // The database stamps createdAt, the route expiresAt: up to a millisecond apart.
    expect(Math.abs(kept.expiresAt.getTime() - kept.createdAt.getTime() - (original - late.createdAt.getTime()))).toBeLessThan(5);
  });

  it('expires a request and closes the released credential with it', async () => {
    const { auth } = await enrolled();
    const { id } = await ask();
    await contribute(bruno, id, true);
    await contribute(alice, id, false);

    await testPrisma.councilRequest.update({ where: { id }, data: { expiresAt: new Date(Date.now() - 1000) } });

    const challenge = (await call<{ challenge_id: string; nonce: string }>(ursula, 'POST', '/api/vault/challenge')).json;
    const proof = await signVaultChallenge(base64ToUint8(challenge.nonce), ursula.id, auth.secretKey);
    expect((await call(ursula, 'POST', '/api/vault/fetch', { challenge_id: challenge.challenge_id, proof: uint8ToBase64(proof) })).status).toBe(401);

    // Closed as expired, and the browser that asked is told so.
    expect((await call(ursula, 'GET', '/api/council-recovery/requests/mine')).json).toMatchObject({ request: null, ended: { reason: 'expired' } });
    expect(await testPrisma.councilRequest.findUniqueOrThrow({ where: { id } })).toMatchObject({ status: 'expired' });
  });

  it('says a request has every part it needs to a custodian who comes late', async () => {
    await enrolled();
    const { id, ephemeral } = await ask();
    await testPrisma.councilRequest.update({ where: { id }, data: { releaseNotBefore: new Date(Date.now() + 60 * 60_000) } });
    await contribute(bruno, id, true);
    expect((await contribute(alice, id, false)).json.stage).toBe('cooldown');

    // Her vault has nothing to open any more (the detail is closed); a share sent anyway is told why.
    const late = await buildContribution({
      requestId: id,
      userId: ursula.id,
      councilId: COUNCIL,
      slot: 3,
      custodianUserId: chloe.id,
      ephemeralPublicKey: ephemeral.publicKey,
      encodedShare: encodeShare({ x: 3, value: randomScalar(), blinding: randomScalar() }),
      inPerson: false,
      identitySecretKey: chloe.identity.secretKey,
    });
    expect((await call(chloe, 'POST', `/api/council-recovery/requests/${id}/contribute`, late, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_ENOUGH_SHARES,
    });
  });

  // Many people asking at once reach the custodians' space, not their inbox, and no request is refused for it.
  it('emails a custodian about new requests at most once an hour', async () => {
    await enrolled();
    await call(victor, 'POST', '/api/councils/escrow', (await enroll(victor, [alice, bruno, chloe])).body, { signed: true });
    const meetings = () => vi.mocked(sendCouncilRecoveryToApprove).mock.calls.filter(([p]) => p.step === 'meet').length;

    await ask();
    expect(meetings()).toBe(3);
    const second = await call(victor, 'POST', '/api/council-recovery/requests', { ephemeral_public_key: uint8ToBase64(new Uint8Array(33)) });
    expect(second.status).toBe(200);
    expect(meetings()).toBe(3);

    // An hour later, the next request is announced again.
    await testPrisma.councilRequestNotice.updateMany({ data: { notifiedAt: new Date(Date.now() - 61 * 60_000) } });
    await call(victor, 'POST', `/api/council-recovery/requests/${second.json.id}/refuse`);
    await call(victor, 'POST', '/api/council-recovery/requests', { ephemeral_public_key: uint8ToBase64(new Uint8Array(33)) });
    expect(meetings()).toBe(6);
  });

  it('asks for a fresh authentication to hand over a share or stop a request', async () => {
    await enrolled();
    const { id } = await ask();
    env.OIDC_STEP_UP_ENABLED = true;
    const refused = { code: API_ERROR_INSUFFICIENT_USER_AUTHENTICATION };

    expect((await contribute(bruno, id, true)).json).toMatchObject(refused);
    expect((await call(chloe, 'POST', `/api/council-recovery/requests/${id}/abort`, undefined, { signed: true })).json).toMatchObject(refused);
    expect(await testPrisma.councilRequest.findUniqueOrThrow({ where: { id } })).toMatchObject({ status: 'open' });
  });
});

describe('resharing', () => {
  it('moves an escrow to the new roster without the user, and the newcomer can then help', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body, secret } = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', body, { signed: true });

    await configure([alice, bruno, denis], 2);
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
        vrk: helper.vrk,
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
          councilId: COUNCIL,
          versions: versionsOf(batch.chain),
          secretKeys: [helper.encryption.secretKey],
        });
        escrows.push(await buildReshareSubShares(target, transferKeys, { id: entry.escrow_id, userId: entry.user_id }, share));
      }

      const uploaded = await call<{ remaining_for_me: number }>(
        helper,
        'POST',
        `/api/councils/reshare/${sessionId}/sub-shares`,
        { escrows },
        { signed: true }
      );
      expect(uploaded.status).toBe(200);
      // Told its part is done, the helper stops: the last upload closes the session, and asking it again is refused.
      expect(uploaded.json.remaining_for_me).toBe(0);
    }
    expect((await testPrisma.councilReshareSession.findFirstOrThrow()).status).toBe('completed');

    const escrow = await testPrisma.councilEscrow.findFirstOrThrow({ include: { capsules: true, rosterVersion: true } });
    expect(escrow.generation).toBe(2);
    expect(escrow.rosterVersion.version).toBe(2);
    expect(escrow.capsules.map((c) => c.slot).sort()).toEqual([1, 2, 4]);

    // Denis's vault checks, on his next visit, what the resharing gave him.
    type Mine = { councils: Array<{ shares_to_check: number; faulty_reshares: unknown[]; health: { ok: number; at_risk: number } }> };
    expect((await call<Mine>(denis, 'GET', '/api/councils/mine')).json.councils[0].shares_to_check).toBe(1);
    const toCheck = (await call<CouncilCheckBatch>(denis, 'GET', `/api/councils/${COUNCIL}/shares-to-check`)).json;
    expect(toCheck.escrows).toHaveLength(1);
    await openCustodianShare(toCheck.escrows[0].capsule, escrowRecordFromWire(ursula.id, toCheck.escrows[0].record), {
      councilId: COUNCIL,
      versions: versionsOf(toCheck.chain),
      secretKeys: [denis.encryption.secretKey],
    });
    const valid = { results: [{ escrow_id: toCheck.escrows[0].escrow_id, valid: true, faulty_helper_slot: null }] };
    expect((await call(denis, 'POST', `/api/councils/${COUNCIL}/shares-checked`, valid, { signed: true })).json).toEqual({ checked: 1, invalid: 0 });
    expect((await call<Mine>(denis, 'GET', '/api/councils/mine')).json.councils[0]).toMatchObject({ shares_to_check: 0, faulty_reshares: [] });

    // Bruno's vault finds Alice's sub-share invalid: his share stops counting, and
    // the council is told who sent it. A second report changes nothing.
    const invalid = { results: [{ escrow_id: toCheck.escrows[0].escrow_id, valid: false, faulty_helper_slot: 1 }] };
    expect((await call(bruno, 'POST', `/api/councils/${COUNCIL}/shares-checked`, invalid, { signed: true })).json).toEqual({
      checked: 1,
      invalid: 1,
    });
    expect((await call(bruno, 'POST', `/api/councils/${COUNCIL}/shares-checked`, valid, { signed: true })).json).toEqual({ checked: 0, invalid: 0 });
    expect((await call<Mine>(alice, 'GET', '/api/councils/mine')).json.councils[0]).toMatchObject({
      faulty_reshares: [{ helper_name: 'Alice Martin', escrows: 1 }],
      health: { ok: 0, at_risk: 1 },
    });
    expect((await call(chloe, 'GET', `/api/councils/${COUNCIL}/shares-to-check`)).status).toBe(403);

    // Denis, who was never given anything by the user, now helps recover her.
    const ephemeral = await generateUserKeyPair();
    const ephemeralWire = base64ToUint8(exportPublicKeyAsBase64(ephemeral.publicKey));
    const { json } = await call<{ id: string }>(ursula, 'POST', '/api/council-recovery/requests', {
      ephemeral_public_key: uint8ToBase64(ephemeralWire),
    });
    expect((await contribute(denis, json.id, true)).json.stage).toBe('collecting');
    expect((await contribute(alice, json.id, false)).json.stage).toBe('released');

    const released = (await call<Parameters<typeof recoverCouncilSecret>[0]>(ursula, 'GET', `/api/council-recovery/requests/${json.id}/shares`)).json;
    expect(
      (await recoverCouncilSecret(released, { publicKey: ephemeralWire, secretKey: ephemeral.secretKey }, wire(ursula.identity))).secret
    ).toEqual(secret);
  });

  it('refuses a helper whose commitments do not start from its own share, and moves nothing', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    const { body } = await enroll(ursula, [alice, bruno, chloe]);
    await call(ursula, 'POST', '/api/councils/escrow', body, { signed: true });

    await configure([alice, bruno, denis], 2);
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
      await call<{ chain: RosterVersionWire[]; helper_slots: number[]; my_slot: number; escrows: Array<{ escrow_id: string; user_id: string }> }>(
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
      vrk: alice.vrk,
      identitySecretKey: alice.identity.secretKey,
    };
    const { body: keys, transferKeys } = await buildReshareKeys({
      ...target,
      recipientKeys: await keysBySlot(batch.chain[batch.chain.length - 1], [alice, bruno, denis]),
    });
    expect((await call(alice, 'POST', `/api/councils/reshare/${sessionId}/keys`, keys, { signed: true })).status).toBe(200);

    // Signed by Alice, but split from a value that is not her share.
    const wrong = encodeShare({ x: batch.my_slot, value: randomScalar(), blinding: randomScalar() });
    const entry = await buildReshareSubShares(target, transferKeys, { id: batch.escrows[0].escrow_id, userId: batch.escrows[0].user_id }, wrong);
    expect(
      (await call<{ code: string }>(alice, 'POST', `/api/councils/reshare/${sessionId}/sub-shares`, { escrows: [entry] }, { signed: true })).json
    ).toMatchObject({ code: API_ERROR_COUNCIL_RESHARE_INVALID });

    // Commitments signed by someone else are refused too.
    const resigned = await buildReshareSubShares(
      { ...target, identitySecretKey: bruno.identity.secretKey },
      transferKeys,
      { id: batch.escrows[0].escrow_id, userId: batch.escrows[0].user_id },
      wrong
    );
    expect((await call(alice, 'POST', `/api/councils/reshare/${sessionId}/sub-shares`, { escrows: [resigned] }, { signed: true })).status).toBe(400);

    expect(await testPrisma.councilReshareCommitment.count()).toBe(0);
    expect((await testPrisma.councilEscrow.findFirstOrThrow()).generation).toBe(1);
  });

  it('refuses helpers that are not threshold custodians of the source still in the head', async () => {
    await bootstrap([alice, bruno, chloe], 2);
    await configure([alice, bruno, denis], 2);
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

  /** Two users enrolled on version 1, then Chloé replaced by Denis (version 2), and a resharing from 1 started by Alice. */
  async function startedResharing(): Promise<{ sessionId: string; escrows: Map<string, string> }> {
    await bootstrap([alice, bruno, chloe], 2);
    for (const user of [ursula, victor]) {
      const { body } = await enroll(user, [alice, bruno, chloe]);
      await call(user, 'POST', '/api/councils/escrow', body, { signed: true });
    }

    await configure([alice, bruno, denis], 2);
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
    const rows = await testPrisma.councilEscrow.findMany();

    return { sessionId: start.json.session_id, escrows: new Map(rows.map((e) => [e.userId, e.id])) };
  }

  /** What a helper's vault does with one batch: keys once, then sub-shares of the escrows asked for (all by default). */
  async function help(helper: Person, sessionId: string, only?: string[]) {
    const batch = (
      await call<{
        chain: RosterVersionWire[];
        helper_slots: number[];
        my_slot: number;
        transfer_keys_done: boolean;
        escrows: Array<{ escrow_id: string; user_id: string; record: Parameters<typeof escrowRecordFromWire>[1]; capsule: CouncilCapsuleWire }>;
      }>(helper, 'GET', `/api/councils/reshare/${sessionId}/batch`)
    ).json;
    const verified = await verifyRosterChain(batch.chain.map((v) => signedVersionFromWire(COUNCIL, v)));
    if (!verified.ok) throw new Error('chain refused');

    const target = {
      sessionId,
      councilId: COUNCIL,
      target: verified.head,
      helperSlots: batch.helper_slots,
      mySlot: batch.my_slot,
      vrk: helper.vrk,
      identitySecretKey: helper.identity.secretKey,
    };
    let transferKeys;
    if (batch.transfer_keys_done) {
      transferKeys = await reshareTransferKeys(target);
    } else {
      const built = await buildReshareKeys({
        ...target,
        recipientKeys: await keysBySlot(batch.chain[batch.chain.length - 1], [alice, bruno, denis]),
      });
      expect((await call(helper, 'POST', `/api/councils/reshare/${sessionId}/keys`, built.body, { signed: true })).status).toBe(200);
      transferKeys = built.transferKeys;
    }

    const escrows = [];
    for (const entry of batch.escrows.filter((e) => !only || only.includes(e.escrow_id))) {
      const share = await openCustodianShare(entry.capsule, escrowRecordFromWire(entry.user_id, entry.record), {
        councilId: COUNCIL,
        versions: versionsOf(batch.chain),
        secretKeys: [helper.encryption.secretKey],
      });
      escrows.push(await buildReshareSubShares(target, transferKeys, { id: entry.escrow_id, userId: entry.user_id }, share));
    }
    if (escrows.length === 0) return null;

    return call<{ moved: number; remaining: number }>(helper, 'POST', `/api/councils/reshare/${sessionId}/sub-shares`, { escrows }, { signed: true });
  }

  /** Denis opens the share a resharing gave him of this user's escrow. */
  async function denisOpens(userId: string) {
    const toCheck = (await call<CouncilCheckBatch>(denis, 'GET', `/api/councils/${COUNCIL}/shares-to-check`)).json;
    const entry = toCheck.escrows.find((e) => e.user_id === userId)!;

    return openCustodianShare(entry.capsule, escrowRecordFromWire(userId, entry.record), {
      councilId: COUNCIL,
      versions: versionsOf(toCheck.chain),
      secretKeys: [denis.encryption.secretKey],
    });
  }

  // The escrows a resharing already moved open only through its keys and
  // sub-shares: stopping it, or a new version taking effect, must not take them.
  it('keeps the escrows already moved when the resharing is stopped', async () => {
    const { sessionId, escrows } = await startedResharing();
    await help(alice, sessionId);
    await help(bruno, sessionId, [escrows.get(ursula.id)!]);

    expect((await testPrisma.councilEscrow.findUniqueOrThrow({ where: { id: escrows.get(ursula.id)! } })).generation).toBe(2);
    expect((await call(alice, 'POST', `/api/councils/reshare/${sessionId}/cancel`, undefined, { signed: true })).json).toEqual({ cancelled: true });

    await denisOpens(ursula.id);
    const victorEscrow = await testPrisma.councilEscrow.findUniqueOrThrow({ where: { id: escrows.get(victor.id)! } });
    expect(victorEscrow.generation).toBe(1);
    expect(await testPrisma.councilSubShare.count({ where: { escrowId: victorEscrow.id } })).toBe(0);
  });

  it('keeps the escrows already moved when a new version takes effect', async () => {
    const { sessionId, escrows } = await startedResharing();
    await help(alice, sessionId);
    await help(bruno, sessionId, [escrows.get(ursula.id)!]);

    await configure([alice, bruno, denis, chloe], 2);
    await signProposal(alice);
    await signProposal(bruno);
    expect((await signProposal(chloe)).activated).toBe(true);

    expect((await testPrisma.councilReshareSession.findUniqueOrThrow({ where: { id: sessionId } })).status).toBe('completed');
    await denisOpens(ursula.id);
  });

  it('takes a helper’s transfer keys once, and a reloaded vault carries on with the same ones', async () => {
    const { sessionId, escrows } = await startedResharing();
    await help(alice, sessionId, [escrows.get(ursula.id)!]);

    const batch = (await call<{ chain: RosterVersionWire[] }>(alice, 'GET', `/api/councils/reshare/${sessionId}/batch`)).json;
    const verified = await verifyRosterChain(batch.chain.map((v) => signedVersionFromWire(COUNCIL, v)));
    if (!verified.ok) throw new Error('chain refused');
    const again = await buildReshareKeys({
      sessionId,
      councilId: COUNCIL,
      target: verified.head,
      helperSlots: [1, 2],
      mySlot: 1,
      vrk: alice.vrk,
      identitySecretKey: alice.identity.secretKey,
      recipientKeys: await keysBySlot(batch.chain[batch.chain.length - 1], [alice, bruno, denis]),
    });
    expect((await call(alice, 'POST', `/api/councils/reshare/${sessionId}/keys`, again.body, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_RESHARE_KEYS_SENT,
    });

    // Alice's second batch uses the keys derived again, as after a reload.
    await help(alice, sessionId);
    await help(bruno, sessionId);
    await denisOpens(ursula.id);
    await denisOpens(victor.id);
    expect((await testPrisma.councilReshareSession.findUniqueOrThrow({ where: { id: sessionId } })).status).toBe('completed');
  });

  it('refuses transfer keys whose binding another custodian signed, and takes the helper’s own afterwards', async () => {
    const { sessionId } = await startedResharing();

    const batch = (await call<{ chain: RosterVersionWire[] }>(alice, 'GET', `/api/councils/reshare/${sessionId}/batch`)).json;
    const verified = await verifyRosterChain(batch.chain.map((v) => signedVersionFromWire(COUNCIL, v)));
    if (!verified.ok) throw new Error('chain refused');
    const signedByBruno = await buildReshareKeys({
      sessionId,
      councilId: COUNCIL,
      target: verified.head,
      helperSlots: [1, 2],
      mySlot: 1,
      vrk: alice.vrk,
      identitySecretKey: bruno.identity.secretKey,
      recipientKeys: await keysBySlot(batch.chain[batch.chain.length - 1], [alice, bruno, denis]),
    });
    expect((await call(alice, 'POST', `/api/councils/reshare/${sessionId}/keys`, signedByBruno.body, { signed: true })).json).toMatchObject({
      code: API_ERROR_COUNCIL_SIGNATURE_INVALID,
    });
    expect(await testPrisma.councilReshareKey.count()).toBe(0);

    await help(alice, sessionId);
    expect(await testPrisma.councilReshareKey.count()).toBeGreaterThan(0);
  });

  it('holds back an escrow with a recovery in progress, and moves it once the request ends', async () => {
    const { sessionId, escrows } = await startedResharing();
    const ephemeral = await generateUserKeyPair();
    const { json } = await call<{ id: string }>(ursula, 'POST', '/api/council-recovery/requests', {
      ephemeral_public_key: exportPublicKeyAsBase64(ephemeral.publicKey),
    });
    expect((await contribute(bruno, json.id, true)).json.stage).toBe('collecting');

    await help(alice, sessionId);
    await help(bruno, sessionId);
    expect((await testPrisma.councilEscrow.findUniqueOrThrow({ where: { id: escrows.get(ursula.id)! } })).generation).toBe(1);
    expect((await testPrisma.councilEscrow.findUniqueOrThrow({ where: { id: escrows.get(victor.id)! } })).generation).toBe(2);

    // Alice's remote share still belongs to the split Bruno's in-person one came from.
    expect((await contribute(alice, json.id, false)).json.stage).toBe('released');

    await call(ursula, 'POST', `/api/council-recovery/requests/${json.id}/refuse`);
    expect((await testPrisma.councilEscrow.findUniqueOrThrow({ where: { id: escrows.get(ursula.id)! } })).generation).toBe(2);
    expect((await testPrisma.councilReshareSession.findUniqueOrThrow({ where: { id: sessionId } })).status).toBe('completed');
  });

  it('asks for a fresh authentication to send, stop or check a resharing', async () => {
    const { sessionId } = await startedResharing();
    env.OIDC_STEP_UP_ENABLED = true;

    const refused = { code: API_ERROR_INSUFFICIENT_USER_AUTHENTICATION };
    expect((await call(alice, 'POST', `/api/councils/reshare/${sessionId}/cancel`, undefined, { signed: true })).json).toMatchObject(refused);
    const keys = { keys: [{ recipient_slot: 1, wrapped_transfer_key: 'AAAA', binding_signature: 'AAAA' }] };
    expect((await call(alice, 'POST', `/api/councils/reshare/${sessionId}/keys`, keys, { signed: true })).json).toMatchObject(refused);
    // The check of received shares runs in the background: signed, without a fresh authentication.
    const results = { results: [{ escrow_id: sessionId, valid: true, faulty_helper_slot: null }] };
    expect((await call(alice, 'POST', `/api/councils/${COUNCIL}/shares-checked`, results, { signed: true })).json).toEqual({
      checked: 0,
      invalid: 0,
    });
  });
});
