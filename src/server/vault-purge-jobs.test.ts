import { type Mock, beforeEach, describe, expect, it, vi } from 'vitest';

import { testPrisma, useTestDatabase } from '@encryption/src/prisma/testing';
import { sendVaultPurgeWarning, sendVaultPurged } from '@encryption/src/server/email/vault-retention';
import { captureServerError } from '@encryption/src/server/monitoring';
import { purgeStep, runVaultPurgeOnce } from '@encryption/src/server/vault-purge-jobs';

vi.mock('@encryption/src/server/env', () => ({ env: { EMAIL_PRODUCT_URL: 'http://localhost:7201' } }));
vi.mock('@encryption/src/server/email/vault-retention');
vi.mock('@encryption/src/server/monitoring', () => ({ captureServerError: vi.fn() }));
vi.mock('@encryption/src/prisma/client', async () => ({
  prisma: (await vi.importActual<typeof import('@encryption/src/prisma/testing')>('@encryption/src/prisma/testing')).testPrisma,
}));

const DAY_MS = 24 * 60 * 60 * 1000;
const NOW = 1_750_000_000_000;
const RETENTION = 730;
const daysAgo = (days: number) => new Date(NOW - days * DAY_MS);

// A warning sent `sentDaysAgo`, announcing the deletion `purgeInDays` from NOW.
const notice = (sentDaysAgo: number, purgeInDays: number) => ({ sentAt: daysAgo(sentDaysAgo), purgeAt: new Date(NOW + purgeInDays * DAY_MS) });

describe('purgeStep', () => {
  it('stays silent while the deletion is more than 30 days away', () => {
    expect(purgeStep(daysAgo(RETENTION - 31), RETENTION, null, NOW)).toEqual({ kind: 'none' });
  });

  it('warns 30 days ahead, announcing the deadline', () => {
    const disabledAt = daysAgo(RETENTION - 30);

    expect(purgeStep(disabledAt, RETENTION, null, NOW)).toEqual({ kind: 'warn', purgeAtMs: NOW + 30 * DAY_MS });
  });

  it('sends the final warning 7 days ahead, once', () => {
    const disabledAt = daysAgo(RETENTION - 7);

    expect(purgeStep(disabledAt, RETENTION, notice(23, 7), NOW)).toEqual({ kind: 'warn', purgeAtMs: NOW + 7 * DAY_MS });
    expect(purgeStep(disabledAt, RETENTION, notice(0, 7), NOW + DAY_MS)).toEqual({ kind: 'none' });
  });

  it('purges at the deadline once warned', () => {
    expect(purgeStep(daysAgo(RETENTION), RETENTION, notice(7, 0), NOW)).toEqual({ kind: 'purge' });
  });

  it('never purges without a warning sent a week earlier', () => {
    // Retention enabled (or shortened) on a vault already past its deadline.
    const disabledAt = daysAgo(RETENTION + 400);

    expect(purgeStep(disabledAt, RETENTION, null, NOW)).toEqual({ kind: 'warn', purgeAtMs: NOW + 7 * DAY_MS });
    expect(purgeStep(disabledAt, RETENTION, notice(3, 4), NOW)).toEqual({ kind: 'none' });
    expect(purgeStep(disabledAt, RETENTION, notice(7, 0), NOW)).toEqual({ kind: 'purge' });
  });

  it('never deletes before the announced date after the retention was shortened', () => {
    // Warned 10 days ago of a deletion 20 days later (730 days), then cut to 180.
    const disabledAt = daysAgo(RETENTION - 20);
    const first = notice(10, 20);

    expect(purgeStep(disabledAt, 180, first, NOW)).toEqual({ kind: 'none' });
    expect(purgeStep(disabledAt, 180, first, NOW + 13 * DAY_MS)).toEqual({ kind: 'warn', purgeAtMs: NOW + 20 * DAY_MS });
    expect(purgeStep(disabledAt, 180, notice(-13, 20), NOW + 20 * DAY_MS)).toEqual({ kind: 'purge' });
  });

  it('sends the final warning late rather than skipping it when ticks were missed', () => {
    // Only the 30-day notice went out, and the job was down from then until after the deadline.
    expect(purgeStep(daysAgo(RETENTION + 1), RETENTION, notice(31, -1), NOW)).toEqual({ kind: 'warn', purgeAtMs: NOW + 7 * DAY_MS });
  });

  it('ignores a notice from an earlier dormancy', () => {
    // Warned, reactivated, then disabled again 10 days ago: the old notice is void.
    expect(purgeStep(daysAgo(10), 180, notice(20, 10), NOW)).toEqual({ kind: 'none' });
    expect(purgeStep(daysAgo(RETENTION), RETENTION, notice(RETENTION + 1, -RETENTION + 29), NOW)).toEqual({
      kind: 'warn',
      purgeAtMs: NOW + 7 * DAY_MS,
    });
  });
});

async function seedVaults(options: {
  disabledAt: Date | null;
  purgeNoticeAt?: Date | null;
  purgeScheduledAt?: Date | null;
  email?: string;
  keyByte?: number;
}) {
  const user = await testPrisma.user.create({ data: { email: options.email ?? 'owner@mail.test', language: 'fr' } });
  const identity = await testPrisma.identity.create({
    data: { userId: user.id, generation: 1, signaturePublicKey: Buffer.from([1, ...new Uint8Array(32).fill(options.keyByte ?? 7)]) },
  });
  const vault = await testPrisma.vaultKeyring.create({
    data: {
      userId: user.id,
      identityId: identity.id,
      disabledAt: options.disabledAt,
      purgeNoticeAt: options.purgeNoticeAt ?? null,
      purgeScheduledAt: options.purgeScheduledAt ?? null,
    },
  });
  await testPrisma.vaultCredential.create({
    data: {
      vaultId: vault.id,
      type: 'primary',
      wrappedVrk: 'd3JhcHBlZA==',
      authPublicKey: Buffer.from(new Uint8Array(32).fill(2)),
      authPubSig: Buffer.from(new Uint8Array(64).fill(3)),
      kdfOps: 3,
      kdfMem: 67108864,
      lang: 'english',
    },
  });

  return { user, identity, vault };
}

describe('runVaultPurgeOnce', () => {
  useTestDatabase();

  beforeEach(() => vi.clearAllMocks());

  it('warns the owner and stamps the vault', async () => {
    const { vault, user } = await seedVaults({ disabledAt: daysAgo(RETENTION - 20) });

    await runVaultPurgeOnce(NOW, RETENTION);

    expect(sendVaultPurgeWarning).toHaveBeenCalledWith(
      expect.objectContaining({ recipient: user.email, locale: 'fr', purgeAtMillis: NOW + 20 * DAY_MS })
    );
    expect(await testPrisma.vaultKeyring.findUniqueOrThrow({ where: { id: vault.id } })).toMatchObject({
      purgeNoticeAt: new Date(NOW),
      purgeScheduledAt: new Date(NOW + 20 * DAY_MS),
    });
  });

  it('keeps waiting when the warning could not be sent', async () => {
    const { vault } = await seedVaults({ disabledAt: daysAgo(RETENTION + 10) });
    (sendVaultPurgeWarning as Mock).mockRejectedValueOnce(new Error('smtp down'));

    await runVaultPurgeOnce(NOW, RETENTION);

    expect((await testPrisma.vaultKeyring.findUniqueOrThrow({ where: { id: vault.id } })).purgeNoticeAt).toBeNull();
    expect(captureServerError).toHaveBeenCalledTimes(1);
  });

  it('reports a failing vault and still processes the next one', async () => {
    const failing = await seedVaults({ disabledAt: daysAgo(RETENTION + 2), purgeNoticeAt: daysAgo(9), purgeScheduledAt: daysAgo(2) });
    const next = await seedVaults({
      disabledAt: daysAgo(RETENTION + 1),
      purgeNoticeAt: daysAgo(8),
      purgeScheduledAt: daysAgo(1),
      email: 'other@mail.test',
      keyByte: 8,
    });
    (sendVaultPurged as Mock).mockRejectedValueOnce(new Error('smtp down'));

    await runVaultPurgeOnce(NOW, RETENTION);

    expect(captureServerError).toHaveBeenCalledTimes(1);
    expect(await testPrisma.vaultKeyring.findUnique({ where: { id: failing.vault.id } })).toBeNull();
    expect(await testPrisma.vaultKeyring.findUnique({ where: { id: next.vault.id } })).toBeNull();
    expect(sendVaultPurged).toHaveBeenCalledTimes(2);
  });

  it('deletes the vault content, keeps the ledger, and tells the owner', async () => {
    const { vault, identity } = await seedVaults({ disabledAt: daysAgo(RETENTION + 1), purgeNoticeAt: daysAgo(8), purgeScheduledAt: daysAgo(1) });

    await runVaultPurgeOnce(NOW, RETENTION);

    expect(await testPrisma.vaultKeyring.findUnique({ where: { id: vault.id } })).toBeNull();
    expect(await testPrisma.vaultCredential.count({ where: { vaultId: vault.id } })).toBe(0);
    expect(await testPrisma.identity.findUnique({ where: { id: identity.id } })).not.toBeNull();
    expect(sendVaultPurged).toHaveBeenCalledWith(expect.objectContaining({ disabledAtMillis: daysAgo(RETENTION + 1).getTime() }));
  });

  it('never touches the active vault', async () => {
    const { vault } = await seedVaults({ disabledAt: null });
    await testPrisma.vaultKeyring.update({ where: { id: vault.id }, data: { createdAt: daysAgo(RETENTION * 3) } });

    await runVaultPurgeOnce(NOW, RETENTION);

    expect(await testPrisma.vaultKeyring.findUnique({ where: { id: vault.id } })).not.toBeNull();
    expect(sendVaultPurgeWarning).not.toHaveBeenCalled();
  });

  it('does nothing when retention is off', async () => {
    const { vault } = await seedVaults({ disabledAt: daysAgo(RETENTION * 3), purgeNoticeAt: daysAgo(30), purgeScheduledAt: daysAgo(23) });

    await runVaultPurgeOnce(NOW, 0);

    expect(await testPrisma.vaultKeyring.findUnique({ where: { id: vault.id } })).not.toBeNull();
  });
});
