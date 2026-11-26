/**
 * Hourly emergency-access jobs. They exist for HUMANS, not for security: the
 * wait deadline itself is enforced lazily (and authoritatively) at every
 * release point (see emergency-core.ts), so a stalled runner can silence
 * notifications but can never lengthen or shorten the wait.
 *
 *  - timeout: flips overdue requests to recovery_approved and emails both
 *    parties (the visible state catches up with the arithmetic);
 *  - reminders: escalating cadence to the grantor while a request runs,
 *    monthly with more than 30 days remaining, weekly under 30, daily during
 *    the final 7, every 6 hours in the final 2 days (the grantor's ability to
 *    object is the entire security of the scheme, so one final-day reminder
 *    like Bitwarden's is not enough for waits that can span holidays);
 *  - purge: never-accepted designations are dropped after 90 days.
 *
 * Multi-instance safety: see startScheduledJob.
 */
import { prisma } from '@encryption/src/prisma/client';
import {
  sendEmergencyRecoveryApprovedContact,
  sendEmergencyRecoveryApprovedGrantor,
  sendEmergencyRecoveryReminder,
} from '@encryption/src/server/email/emergency';
import { env } from '@encryption/src/server/env';
import { DAY_MS, HOUR_MS, emergencyRecipient } from '@encryption/src/server/routes/emergency-core';
import { startScheduledJob } from '@encryption/src/server/scheduled-job';

export const EMERGENCY_JOBS_INTERVAL_MS = 60 * 60 * 1000;
// How long one run may hold the advisory lock. Well under the hourly interval,
// well over the SMTP latency of a realistic batch (see startScheduledJob).
export const EMERGENCY_JOBS_LOCK_TIMEOUT_MS = 10 * 60 * 1000;
const INVITED_PURGE_AFTER_MS = 90 * DAY_MS;
const ADVISORY_LOCK_KEY = 'encryption-emergency-jobs';

export interface ReminderDecision {
  due: boolean;
  daysRemaining: number;
}

/**
 * Whether a reminder is due NOW for a running request, and how many days
 * remain. Pure so the cadence is directly testable: the throttle interval
 * depends on the time REMAINING, measured against lastNotifiedAt.
 *
 * The bottom tier (6 hours under 2 days) exists because `lastNotifiedAt` is
 * stamped at initiate: with a daily floor, the shortest allowed wait (1 day)
 * would see its first reminder fall due exactly at the deadline, by which point
 * the timeout job has already flipped the row out of `recoveryRequested` and the
 * reminder query no longer matches it. A 1-day wait would get no reminder at all
 * — the one length where the grantor has the least time to react.
 */
export function reminderDue(recoveryRequestedAt: Date, waitTimeDays: number, lastNotifiedAt: Date | null, nowMs: number): ReminderDecision {
  const deadlineMs = recoveryRequestedAt.getTime() + waitTimeDays * DAY_MS;
  const remainingMs = deadlineMs - nowMs;
  const daysRemaining = Math.max(0, Math.ceil(remainingMs / DAY_MS));

  if (remainingMs <= 0) return { due: false, daysRemaining: 0 };

  const throttleMs =
    remainingMs <= 2 * DAY_MS ? 6 * HOUR_MS : remainingMs <= 7 * DAY_MS ? DAY_MS : remainingMs <= 30 * DAY_MS ? 7 * DAY_MS : 30 * DAY_MS;
  const lastMs = lastNotifiedAt?.getTime() ?? recoveryRequestedAt.getTime();

  return { due: nowMs - lastMs >= throttleMs, daysRemaining };
}

async function runTimeoutJob(nowMs: number): Promise<void> {
  const rows = await prisma.emergencyAccess.findMany({ where: { status: 'recoveryRequested' } });
  const overdue = rows.filter((row) => row.recoveryRequestedAt !== null && row.recoveryRequestedAt.getTime() + row.waitTimeDays * DAY_MS <= nowMs);

  for (const row of overdue) {
    // Guarded flip: a concurrent reject/cancel or the lazy flip in /recover wins.
    const updated = await prisma.emergencyAccess.updateMany({
      where: { id: row.id, status: 'recoveryRequested' },
      data: { status: 'recoveryApproved' },
    });
    if (updated.count === 0) continue;

    const [grantor, grantee] = await Promise.all([emergencyRecipient(row.grantorUserId), emergencyRecipient(row.granteeUserId)]);
    if (!grantor || !grantee) continue;

    const productUrl = env.EMAIL_PRODUCT_URL ?? '';
    await Promise.all([
      sendEmergencyRecoveryApprovedGrantor({ recipient: grantor.email, locale: grantor.locale, grantee: grantee.labelWithEmail, productUrl }),
      sendEmergencyRecoveryApprovedContact({ recipient: grantee.email, locale: grantee.locale, grantor: grantor.label, productUrl }),
    ]).catch((err) => console.error('emergency timeout emails failed', err));
  }
}

async function runReminderJob(nowMs: number): Promise<void> {
  const rows = await prisma.emergencyAccess.findMany({ where: { status: 'recoveryRequested' } });

  for (const row of rows) {
    if (row.recoveryRequestedAt === null) continue;

    const decision = reminderDue(row.recoveryRequestedAt, row.waitTimeDays, row.lastNotifiedAt, nowMs);
    if (!decision.due) continue;

    const [grantor, grantee] = await Promise.all([emergencyRecipient(row.grantorUserId), emergencyRecipient(row.granteeUserId)]);
    if (!grantor || !grantee) continue;

    try {
      await sendEmergencyRecoveryReminder({
        recipient: grantor.email,
        locale: grantor.locale,
        grantee: grantee.labelWithEmail,
        daysRemaining: decision.daysRemaining,
        productUrl: env.EMAIL_PRODUCT_URL ?? '',
      });
      await prisma.emergencyAccess.update({ where: { id: row.id }, data: { lastNotifiedAt: new Date(nowMs) } });
    } catch (err) {
      // Do not bump lastNotifiedAt on failure: the next tick retries.
      console.error('emergency reminder email failed', err);
    }
  }
}

async function runInvitedPurgeJob(nowMs: number): Promise<void> {
  const stale = await prisma.emergencyAccess.findMany({ where: { status: 'invited', createdAt: { lt: new Date(nowMs - INVITED_PURGE_AFTER_MS) } } });

  for (const row of stale) {
    // Deleting the credential cascades the relationship row away.
    await prisma.vaultCredential.deleteMany({ where: { id: row.credentialId } });
  }
}

/** One tick. Exported for tests; the lock lives in the caller. */
export async function runEmergencyJobsOnce(nowMs: number): Promise<void> {
  await runTimeoutJob(nowMs);
  await runReminderJob(nowMs);
  await runInvitedPurgeJob(nowMs);
}

export function startEmergencyJobs(): () => Promise<void> {
  return startScheduledJob({
    lockKey: ADVISORY_LOCK_KEY,
    intervalMs: EMERGENCY_JOBS_INTERVAL_MS,
    lockTimeoutMs: EMERGENCY_JOBS_LOCK_TIMEOUT_MS,
    run: runEmergencyJobsOnce,
    label: 'emergency jobs',
  });
}
