import {
  type EscrowHealthStatus,
  type Tx,
  absentAmong,
  activeIdentityIdsOf,
  councilHead,
  escrowHealth,
  headHealth,
  lastSignInsOf,
  worseHealth,
} from '@encryption/src/server/council-core';
import type { RecoveryCouncilConfig } from '@encryption/src/server/recovery-councils';
import { userFullName } from '@encryption/src/server/user-name';

/**
 * Nobody resigns from a council: people leave the organization, change jobs, or
 * stop signing in. Computed at each sync, two notices make that visible before a
 * recovery fails on it: the custodians are told when the council's health gets
 * worse, and a custodian long absent is asked to sign in once.
 */

/** The health custodians are told about: `blocked` when everyone is still covered but a custodian without encryption stops anyone joining. */
export type CouncilAlertStatus = EscrowHealthStatus | 'blocked';

const ALERT_RANK: Record<CouncilAlertStatus, number> = { ok: 0, blocked: 1, 'at-risk': 2, lost: 3 };

export interface CouncilHealthAlert {
  status: Exclude<CouncilAlertStatus, 'ok'>;
  /** People the council can no longer give their access back. */
  lost: number;
  /** Names of the custodians counted absent. */
  absent: string[];
  /** Names of the custodians whose identity in the head is no longer active. */
  inactive: string[];
  /** Nobody inactive: the people lost can join again right away. */
  teamReady: boolean;
  absenceDays: number;
  /** The custodians of the head who still hold a key it names. */
  userIds: string[];
}

export interface CouncilAlerts {
  health: CouncilHealthAlert | null;
  /** Custodians to ask to sign in. */
  absenceReminders: string[];
}

function isAlertStatus(value: string): value is CouncilAlertStatus {
  return value in ALERT_RANK;
}

/** Told when the health gets worse than what they were last told; a recovery resets it silently. */
export function healthAlertDue(previous: string | null, status: CouncilAlertStatus): boolean {
  return ALERT_RANK[status] > ALERT_RANK[previous !== null && isAlertStatus(previous) ? previous : 'ok'];
}

/** Asked once per absence: a sign-in after the reminder ends it, a later absence asks again. */
export function absenceReminderDue(notifiedAtMillis: number | null, lastSignInMillis: number): boolean {
  return notifiedAtMillis === null || notifiedAtMillis < lastSignInMillis;
}

/**
 * The notices one council needs now, recorded as sent in the same transaction
 * (taken under the sync's advisory lock), so several instances send each once.
 */
export async function claimCouncilAlerts(
  config: Pick<RecoveryCouncilConfig, 'id' | 'absenceDays'>,
  tx: Tx,
  now = Date.now()
): Promise<CouncilAlerts> {
  const head = await councilHead(config.id, tx);
  if (!head) return { health: null, absenceReminders: [] };

  const escrows = await tx.councilEscrow.findMany({ where: { councilId: config.id }, include: { capsules: true } });
  const identityIds = [...head.members.map((m) => m.identityId), ...escrows.flatMap((e) => e.capsules.map((c) => c.identityId))];
  const active = await activeIdentityIdsOf([...new Set(identityIds)], tx);
  const userIds = head.members.map((m) => m.userId);
  const lastSignIns = await lastSignInsOf(userIds, tx);
  const absent = absentAmong(lastSignIns, userIds, config.absenceDays, now);
  const statuses = escrows.map((escrow) => escrowHealth(escrow, head, active, absent).status);
  const health = statuses.reduce(worseHealth, headHealth(head, active, absent));
  const live = head.members.filter((m) => active.has(m.identityId));
  const teamReady = live.length === head.members.length;
  const status: CouncilAlertStatus = health === 'ok' && !teamReady ? 'blocked' : health;
  const nameOf = (m: (typeof head.members)[number]) => userFullName(m.user) ?? m.user.email;

  let alert: CouncilHealthAlert | null = null;
  const previous = await tx.councilHealthNotice.findUnique({ where: { councilId: config.id } });

  if (previous?.status !== status) {
    await tx.councilHealthNotice.upsert({
      where: { councilId: config.id },
      create: { councilId: config.id, status },
      update: { status, notifiedAt: new Date(now) },
    });

    if (status !== 'ok' && healthAlertDue(previous?.status ?? null, status)) {
      alert = {
        status,
        lost: statuses.filter((s) => s === 'lost').length,
        absent: live.filter((m) => absent.has(m.userId)).map(nameOf),
        inactive: head.members.filter((m) => !active.has(m.identityId)).map(nameOf),
        teamReady,
        absenceDays: config.absenceDays,
        userIds: live.map((m) => m.userId),
      };
    }
  }

  const notices = new Map(
    (await tx.councilAbsenceNotice.findMany({ where: { councilId: config.id } })).map((n) => [n.userId, n.notifiedAt.getTime()])
  );
  const absenceReminders = live
    .map((m) => m.userId)
    .filter((userId) => absent.has(userId) && absenceReminderDue(notices.get(userId) ?? null, lastSignIns.get(userId) ?? 0));

  for (const userId of absenceReminders) {
    await tx.councilAbsenceNotice.upsert({
      where: { councilId_userId: { councilId: config.id, userId } },
      create: { councilId: config.id, userId },
      update: { notifiedAt: new Date(now) },
    });
  }

  return { health: alert, absenceReminders };
}
