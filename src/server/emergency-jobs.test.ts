import { testPrisma, useTestDatabase } from '@encryption/src/prisma/testing';
import {
  sendEmergencyRecoveryApprovedContact,
  sendEmergencyRecoveryApprovedGrantor,
  sendEmergencyRecoveryReminder,
} from '@encryption/src/server/email/emergency';
import { reminderDue, runEmergencyJobsOnce } from '@encryption/src/server/emergency-jobs';

jest.mock('@encryption/src/server/env', () => ({ env: { EMAIL_PRODUCT_URL: 'http://localhost:7201' } }));

// Shared manual mock: every send is an inert jest.fn this suite asserts on.
jest.mock('@encryption/src/server/email/emergency');

// The database is real (in-process Postgres), so the jobs run their actual
// queries and the cascade that purges a designation is the database's own.
jest.mock('@encryption/src/prisma/client', () => ({ prisma: jest.requireActual('@encryption/src/prisma/testing').testPrisma }));

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const NOW = 1_750_000_000_000;

// The escalating cadence is the timing-sensitive core: it must email often
// enough that a grantor can object, without spamming a 90-day wait.
describe('reminderDue (escalating cadence)', () => {
  const started = (daysAgo: number) => new Date(NOW - daysAgo * DAY_MS);

  it('is silent while the previous notification is fresher than the throttle', () => {
    // 60 days remain (90-day wait, 30 elapsed): monthly cadence.
    expect(reminderDue(started(30), 90, new Date(NOW - 10 * DAY_MS), NOW).due).toBe(false);
    // 20 days remain: weekly cadence, last notified 3 days ago.
    expect(reminderDue(started(10), 30, new Date(NOW - 3 * DAY_MS), NOW).due).toBe(false);
    // 3 days remain: daily cadence, last notified 2 hours ago.
    expect(reminderDue(started(4), 7, new Date(NOW - 2 * 60 * 60 * 1000), NOW).due).toBe(false);
  });

  it('fires monthly with more than 30 days remaining', () => {
    const decision = reminderDue(started(31), 90, new Date(NOW - 31 * DAY_MS), NOW);

    expect(decision.due).toBe(true);
    expect(decision.daysRemaining).toBe(59);
  });

  it('fires weekly during the last 30 days', () => {
    const decision = reminderDue(started(10), 30, new Date(NOW - 8 * DAY_MS), NOW);

    expect(decision.due).toBe(true);
    expect(decision.daysRemaining).toBe(20);
  });

  it('fires daily during the final 7 days', () => {
    const decision = reminderDue(started(5), 7, new Date(NOW - 25 * 60 * 60 * 1000), NOW);

    expect(decision.due).toBe(true);
    expect(decision.daysRemaining).toBe(2);
  });

  it('falls back to the request date when nothing was ever sent', () => {
    expect(reminderDue(started(8), 30, null, NOW).due).toBe(true);
  });

  it('reminds the grantor at least once on the SHORTEST allowed wait', () => {
    // 1 day is the minimum the server accepts, and `lastNotifiedAt` is stamped at
    // initiate. On a daily floor the first reminder would fall due exactly at the
    // deadline, by which point the timeout job has already moved the row out of
    // `recoveryRequested` and the reminder query no longer sees it — no reminder
    // at all, on the wait that leaves the grantor the least time to object.
    const initiatedAt = new Date(NOW - 6 * HOUR_MS);

    expect(reminderDue(initiatedAt, 1, initiatedAt, NOW).due).toBe(true);
    // Still throttled four hours in.
    expect(reminderDue(new Date(NOW - 4 * HOUR_MS), 1, new Date(NOW - 4 * HOUR_MS), NOW).due).toBe(false);
  });

  it('never fires past the deadline (the timeout job owns that moment)', () => {
    expect(reminderDue(started(16), 15, null, NOW).due).toBe(false);
  });
});

interface RelationshipOptions {
  status: 'invited' | 'confirmed' | 'recoveryRequested' | 'recoveryApproved';
  waitTimeDays: number;
  recoveryRequestedAt?: Date | null;
  lastNotifiedAt?: Date | null;
  createdAt?: Date;
}

/** A grantor with a vault plus a dormant emergency credential escrowed to a contact. */
async function seedRelationship(options: RelationshipOptions) {
  const grantor = await testPrisma.user.create({ data: { email: 'grantor@mail.test' } });
  const grantee = await testPrisma.user.create({ data: { email: 'grantee@mail.test' } });

  const identity = await testPrisma.identity.create({
    data: { userId: grantor.id, generation: 1, signaturePublicKey: Buffer.from([1, ...new Uint8Array(32).fill(7)]) },
  });
  const granteeIdentity = await testPrisma.identity.create({
    data: { userId: grantee.id, generation: 1, signaturePublicKey: Buffer.from([1, ...new Uint8Array(32).fill(4)]) },
  });
  const vault = await testPrisma.vaultKeyring.create({ data: { userId: grantor.id, identityId: identity.id } });

  const credential = await testPrisma.vaultCredential.create({
    data: {
      vaultId: vault.id,
      type: 'emergency',
      wrappedVrk: 'd3JhcHBlZA==',
      authPublicKey: Buffer.from(new Uint8Array(32).fill(2)),
      authPubSig: Buffer.from(new Uint8Array(64).fill(3)),
      kdfOps: 3,
      kdfMem: 67108864,
      lang: 'english',
    },
  });

  const relationship = await testPrisma.emergencyAccess.create({
    data: {
      grantorUserId: grantor.id,
      granteeUserId: grantee.id,
      status: options.status,
      waitTimeDays: options.waitTimeDays,
      credentialId: credential.id,
      wrappedPhraseForGrantee: 'Y2Fwc3VsZQ==',
      granteeIdentityId: granteeIdentity.id,
      granteeKeyVersion: 1,
      escrowSignature: Buffer.from(new Uint8Array(64).fill(5)),
      escrowCreatedAt: new Date(NOW - 60 * DAY_MS),
      recoveryRequestedAt: options.recoveryRequestedAt ?? null,
      lastNotifiedAt: options.lastNotifiedAt ?? null,
      createdAt: options.createdAt ?? new Date(NOW - 30 * DAY_MS),
    },
  });

  return { grantor, grantee, vault, credential, relationship };
}

describe('runEmergencyJobsOnce', () => {
  useTestDatabase();

  beforeEach(() => jest.clearAllMocks());

  it('flips overdue requests and emails both parties', async () => {
    const { relationship } = await seedRelationship({
      status: 'recoveryRequested',
      waitTimeDays: 7,
      recoveryRequestedAt: new Date(NOW - 8 * DAY_MS),
    });

    await runEmergencyJobsOnce(NOW);

    expect((await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: relationship.id } })).status).toBe('recoveryApproved');
    expect(sendEmergencyRecoveryApprovedGrantor).toHaveBeenCalled();
    expect(sendEmergencyRecoveryApprovedContact).toHaveBeenCalled();
  });

  it('leaves a request that is still inside its wait period alone', async () => {
    const { relationship } = await seedRelationship({
      status: 'recoveryRequested',
      waitTimeDays: 30,
      recoveryRequestedAt: new Date(NOW - 2 * DAY_MS),
      lastNotifiedAt: new Date(NOW - 1 * DAY_MS),
    });

    await runEmergencyJobsOnce(NOW);

    expect((await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: relationship.id } })).status).toBe('recoveryRequested');
    expect(sendEmergencyRecoveryApprovedGrantor).not.toHaveBeenCalled();
  });

  it('skips the emails when a concurrent actor already moved the row', async () => {
    const { relationship } = await seedRelationship({
      status: 'recoveryRequested',
      waitTimeDays: 7,
      recoveryRequestedAt: new Date(NOW - 8 * DAY_MS),
    });

    // The guarded flip is a single UPDATE ... WHERE status = 'recoveryRequested',
    // so moving the row first reproduces the lost race without a second session:
    // the job's own statement matches nothing and it must stay silent.
    await testPrisma.emergencyAccess.update({ where: { id: relationship.id }, data: { status: 'confirmed' } });

    await runEmergencyJobsOnce(NOW);

    expect(sendEmergencyRecoveryApprovedGrantor).not.toHaveBeenCalled();
    expect((await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: relationship.id } })).status).toBe('confirmed');
  });

  it('sends a due reminder and bumps lastNotifiedAt only on success', async () => {
    const { relationship } = await seedRelationship({
      status: 'recoveryRequested',
      waitTimeDays: 30,
      recoveryRequestedAt: new Date(NOW - 10 * DAY_MS),
      lastNotifiedAt: new Date(NOW - 8 * DAY_MS),
    });

    await runEmergencyJobsOnce(NOW);

    expect(sendEmergencyRecoveryReminder).toHaveBeenCalledWith(expect.objectContaining({ daysRemaining: 20 }));
    expect((await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: relationship.id } })).lastNotifiedAt).toEqual(new Date(NOW));
  });

  it('does not bump lastNotifiedAt when the reminder send fails (the next tick retries)', async () => {
    const lastNotifiedAt = new Date(NOW - 8 * DAY_MS);
    const { relationship } = await seedRelationship({
      status: 'recoveryRequested',
      waitTimeDays: 30,
      recoveryRequestedAt: new Date(NOW - 10 * DAY_MS),
      lastNotifiedAt,
    });

    (sendEmergencyRecoveryReminder as jest.Mock).mockRejectedValueOnce(new Error('smtp down'));
    jest.spyOn(console, 'error').mockImplementation(() => {});

    await runEmergencyJobsOnce(NOW);

    expect((await testPrisma.emergencyAccess.findUniqueOrThrow({ where: { id: relationship.id } })).lastNotifiedAt).toEqual(lastNotifiedAt);
  });

  it('purges never-accepted designations after 90 days via their credential', async () => {
    const { relationship, credential } = await seedRelationship({
      status: 'invited',
      waitTimeDays: 7,
      createdAt: new Date(NOW - 91 * DAY_MS),
    });

    await runEmergencyJobsOnce(NOW);

    // Deleting the credential cascades the relationship row away, for real.
    expect(await testPrisma.vaultCredential.findUnique({ where: { id: credential.id } })).toBeNull();
    expect(await testPrisma.emergencyAccess.findUnique({ where: { id: relationship.id } })).toBeNull();
  });

  it('keeps a designation that is still inside the 90-day window', async () => {
    const { relationship } = await seedRelationship({
      status: 'invited',
      waitTimeDays: 7,
      createdAt: new Date(NOW - 89 * DAY_MS),
    });

    await runEmergencyJobsOnce(NOW);

    expect(await testPrisma.emergencyAccess.findUnique({ where: { id: relationship.id } })).not.toBeNull();
  });
});
