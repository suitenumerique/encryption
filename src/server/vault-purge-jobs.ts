/**
 * Retention of dormant vaults: a vault left behind by a start-over, or by leaving
 * encryption, stays restorable by its own recovery phrase for
 * VAULT_PURGE_AFTER_DAYS, then its content (credentials, sealed items, manifest,
 * and through them the emergency escrows) is deleted. The active vault is never
 * concerned, and the directory ledger (identities, key versions) is kept forever.
 *
 * The user is warned 30 days, then 7 days, before the deletion, and told once it
 * happened. A deletion never runs without a warning sent at least 7 days earlier
 * in the same dormancy: enabling the job on a deployment that already holds old
 * dormant vaults, or shortening the retention, warns first and deletes a week
 * later instead of deleting at the first tick.
 */
import { prisma } from '@encryption/src/prisma/client';
import { sendVaultPurgeWarning, sendVaultPurged } from '@encryption/src/server/email/vault-retention';
import { env } from '@encryption/src/server/env';
import { captureServerError } from '@encryption/src/server/monitoring';
import { DAY_MS, emergencyRecipient } from '@encryption/src/server/routes/emergency-core';
import { startScheduledJob } from '@encryption/src/server/scheduled-job';

const FIRST_NOTICE_MS = 30 * DAY_MS;
const FINAL_NOTICE_MS = 7 * DAY_MS;
const LOCK_KEY = 'encryption-vault-purge';

export type PurgeStep = { kind: 'none' } | { kind: 'warn'; purgeAtMs: number } | { kind: 'purge' };

export interface PurgeNotice {
  /** When the last warning was sent. */
  sentAt: Date;
  /** The deletion date that warning announced. */
  purgeAt: Date;
}

/**
 * What a dormant vault needs now. A notice sent before `disabledAt` belongs to an
 * earlier dormancy (the vault was reactivated since), so it does not count.
 *
 * Once warned, the vault is never deleted before the date the warning announced,
 * even if the retention was shortened since; and a notice sent more than a week
 * before the deletion date (the first one, or one whose date moved later since)
 * is followed by a final one in the last week, late rather than never when ticks
 * were missed.
 */
export function purgeStep(disabledAt: Date, purgeAfterDays: number, notice: PurgeNotice | null, nowMs: number): PurgeStep {
  const deadlineMs = disabledAt.getTime() + purgeAfterDays * DAY_MS;
  const current = notice && notice.sentAt.getTime() >= disabledAt.getTime() ? notice : null;

  if (current === null) {
    if (deadlineMs - nowMs > FIRST_NOTICE_MS) return { kind: 'none' };

    return { kind: 'warn', purgeAtMs: Math.max(deadlineMs, nowMs + FINAL_NOTICE_MS) };
  }

  const purgeAtMs = Math.max(deadlineMs, current.purgeAt.getTime());

  if (purgeAtMs - nowMs <= FINAL_NOTICE_MS && current.sentAt.getTime() < purgeAtMs - FINAL_NOTICE_MS) {
    return { kind: 'warn', purgeAtMs: Math.max(purgeAtMs, nowMs + FINAL_NOTICE_MS) };
  }

  if (nowMs >= purgeAtMs) return { kind: 'purge' };

  return { kind: 'none' };
}

/** One tick. Exported for tests; the lock lives in the caller. */
export async function runVaultPurgeOnce(nowMs: number, purgeAfterDays: number): Promise<void> {
  if (purgeAfterDays === 0) return;

  // Only vaults close enough to their deadline to need a notice or a deletion.
  const candidates = await prisma.vaultKeyring.findMany({
    where: { disabledAt: { not: null, lte: new Date(nowMs - purgeAfterDays * DAY_MS + FIRST_NOTICE_MS) } },
    select: { id: true, userId: true, disabledAt: true, purgeNoticeAt: true, purgeScheduledAt: true },
  });

  for (const vault of candidates) {
    // One vault failing must not hold back the others, and must reach the
    // operators: the next tick retries it, and a deletion still waits for a
    // warning that was actually sent.
    try {
      await processVault({ ...vault, disabledAt: vault.disabledAt as Date }, nowMs, purgeAfterDays);
    } catch (err) {
      console.error(`vault purge failed for vault ${vault.id}`, err);
      captureServerError(err, { tags: { code: LOCK_KEY } });
    }
  }
}

interface DormantVault {
  id: string;
  userId: string;
  disabledAt: Date;
  purgeNoticeAt: Date | null;
  purgeScheduledAt: Date | null;
}

async function processVault(
  { id: vaultId, userId, disabledAt, purgeNoticeAt, purgeScheduledAt }: DormantVault,
  nowMs: number,
  purgeAfterDays: number
): Promise<void> {
  const notice = purgeNoticeAt && purgeScheduledAt ? { sentAt: purgeNoticeAt, purgeAt: purgeScheduledAt } : null;
  const step = purgeStep(disabledAt, purgeAfterDays, notice, nowMs);

  if (step.kind === 'none') return;

  const recipient = await emergencyRecipient(userId);

  if (step.kind === 'warn') {
    // No address, no warning, and therefore no deletion: the purge waits for a
    // notice that was actually sent.
    if (!recipient) return;

    await sendVaultPurgeWarning({
      recipient: recipient.email,
      locale: recipient.locale,
      disabledAtMillis: disabledAt.getTime(),
      purgeAtMillis: step.purgeAtMs,
      productUrl: env.EMAIL_PRODUCT_URL,
    });
    await prisma.vaultKeyring.updateMany({
      where: { id: vaultId, disabledAt },
      data: { purgeNoticeAt: new Date(nowMs), purgeScheduledAt: new Date(step.purgeAtMs) },
    });

    return;
  }

  // Guarded on the `disabledAt` just read: a vault reactivated (or reactivated
  // and disabled again) since is not the one that was warned about.
  const deleted = await prisma.vaultKeyring.deleteMany({ where: { id: vaultId, disabledAt } });
  if (deleted.count === 0) return;

  console.info(`dormant vault purged (user ${userId}, vault ${vaultId})`);

  if (recipient) await sendVaultPurged({ recipient: recipient.email, locale: recipient.locale, disabledAtMillis: disabledAt.getTime() });
}

export function startVaultPurgeJobs(): () => Promise<void> {
  return startScheduledJob({
    lockKey: LOCK_KEY,
    intervalMs: 60 * 60 * 1000,
    lockTimeoutMs: 10 * 60 * 1000,
    run: (nowMs) => runVaultPurgeOnce(nowMs, env.VAULT_PURGE_AFTER_DAYS),
    label: 'vault purge',
  });
}
