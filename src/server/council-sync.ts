/**
 * Turn the configuration (RECOVERY_COUNCILS) into proposals for the custodians to
 * sign, at boot and then periodically, never from a request: a read must not
 * replace a proposal (and its signatures) nor send email.
 *
 * Several instances may run it: a transaction-scoped advisory lock lets one of
 * them work at a time, and a proposal is emailed once per content, so a
 * configuration that flips (two values during a rolling deploy) does not mail
 * the custodians at every flip.
 */
import type { FastifyBaseLogger } from 'fastify';

import { prisma } from '@encryption/src/prisma/client';
import {
  type Db,
  configuredCouncils,
  councilHead,
  councilLabel,
  escrowsLostByChange,
  syncCouncilProposal,
} from '@encryption/src/server/council-core';
import { type CouncilAlerts, claimCouncilAlerts } from '@encryption/src/server/council-health-alerts';
import { claimReadyNotice, readyNoticeCandidates, waitingReadyNotices } from '@encryption/src/server/council-requests-core';
import { moveCompleteEscrows } from '@encryption/src/server/council-reshare-core';
import {
  sendCouncilAbsenceReminder,
  sendCouncilHealthAlert,
  sendCouncilRecoveryReady,
  sendCouncilRosterToSign,
} from '@encryption/src/server/email/council';
import { env } from '@encryption/src/server/env';
import { COUNCIL_DEFAULT_ABSENCE_DAYS, type RecoveryCouncilConfig } from '@encryption/src/server/recovery-councils';
import { emergencyRecipient } from '@encryption/src/server/routes/emergency-core';

// Identity changes sync at once (`syncCouncilsAfterIdentityChange`) and a configuration change
// needs a restart, which syncs at boot: what is left (an email changed at sign-in, absences
// and health alerts, purges) counts in days.
const SYNC_INTERVAL_MS = 60 * 60 * 1000;
// Arbitrary, fixed: the key of the advisory lock only council syncs take.
const SYNC_LOCK_KEY = 7_200_001;

/** Sync every configured council once. Returns false when another instance holds the lock. */
export async function syncConfiguredCouncils(log: FastifyBaseLogger): Promise<boolean> {
  const toNotify: Array<{ councilId: string; label: string; userIds: string[] }> = [];
  const alerts: Array<{ config: Pick<RecoveryCouncilConfig, 'id' | 'label' | 'absenceDays'> } & CouncilAlerts> = [];

  const locked = await prisma.$transaction(
    async (tx) => {
      const [{ locked }] = await tx.$queryRaw<Array<{ locked: boolean }>>`SELECT pg_try_advisory_xact_lock(${SYNC_LOCK_KEY}) AS locked`;
      if (!locked) return false;

      for (const config of configuredCouncils()) {
        await tx.councilLabel.upsert({
          where: { councilId: config.id },
          create: { councilId: config.id, label: config.label },
          update: { label: config.label },
        });
        const result = await syncCouncilProposal(config, tx);
        alerts.push({ config, ...(await claimCouncilAlerts(config, tx)) });
        if (!result.proposal) continue;

        const current = await councilHead(config.id, tx);
        const lost = current ? await escrowsLostByChange(current, result.proposal, tx) : 0;
        if (lost > 0)
          log.warn(
            `Recovery council "${config.id}": the proposed membership keeps too few current custodians, ${lost} escrow(s) would no longer be recoverable once it takes effect. Remove fewer custodians at once (keep at least as many as the threshold), move the escrows, then remove the rest.`
          );

        const notice = await tx.councilProposalNotice.createMany({
          data: [{ councilId: config.id, rosterHash: result.proposal.rosterHash }],
          skipDuplicates: true,
        });
        if (notice.count === 0) continue;

        const head = await councilHead(config.id, tx);
        toNotify.push({
          councilId: config.id,
          label: config.label,
          userIds: [...new Set([...result.proposal.members.map((m) => m.userId), ...(head?.members.map((m) => m.userId) ?? [])])],
        });
      }

      // Out of the configuration but still protecting people: their custodians still need to hear when it degrades.
      for (const { councilId } of await unconfiguredCouncilsWithEscrows(tx)) {
        const config = { id: councilId, label: await councilLabel(councilId, tx), absenceDays: COUNCIL_DEFAULT_ABSENCE_DAYS };
        alerts.push({ config, ...(await claimCouncilAlerts(config, tx)) });
      }

      return true;
    },
    { timeout: 30_000 }
  );

  const productUrl = env.EMAIL_PRODUCT_URL ?? '';
  for (const { label, userIds } of toNotify) {
    for (const userId of userIds) {
      const recipient = await emergencyRecipient(userId);
      if (recipient)
        sendCouncilRosterToSign({ recipient: recipient.email, locale: recipient.locale, council: label, productUrl }).catch((err: unknown) =>
          log.error({ err }, 'recovery council email failed: roster to sign')
        );
    }
  }

  for (const { config, health, absenceReminders } of alerts) {
    if (health) {
      log.warn(
        `Recovery council "${config.id}" is ${health.status}: ${health.lost} escrow(s) no longer recoverable, ${health.absent.length} custodian(s) without a sign-in for ${health.absenceDays} days, ${health.inactive.length} without an active identity. Name new custodians in RECOVERY_COUNCILS if some left.`
      );
      for (const userId of health.userIds) {
        const recipient = await emergencyRecipient(userId);
        if (recipient)
          sendCouncilHealthAlert({
            recipient: recipient.email,
            locale: recipient.locale,
            council: config.label,
            status: health.status,
            lost: health.lost,
            absent: health.absent,
            inactive: health.inactive,
            teamReady: health.teamReady,
            absenceDays: health.absenceDays,
            productUrl,
          }).catch((err: unknown) => log.error({ err }, 'recovery council email failed: health alert'));
      }
    }

    for (const userId of absenceReminders) {
      const recipient = await emergencyRecipient(userId);
      if (recipient)
        sendCouncilAbsenceReminder({
          recipient: recipient.email,
          locale: recipient.locale,
          council: config.label,
          absenceDays: config.absenceDays,
          productUrl,
        }).catch((err: unknown) => log.error({ err }, 'recovery council email failed: absence reminder'));
    }
  }

  return locked;
}

// A closed request is kept a while for the daily limits on asking and the user's notice, then purged.
const CLOSED_REQUEST_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Councils that still hold escrows but are no longer in the configuration. A
 * council is its `id`: renaming one starts a new council beside the old, whose
 * users stay on it, so a rename or a removal by mistake must not go unnoticed.
 */
export async function unconfiguredCouncilsWithEscrows(db: Db = prisma): Promise<Array<{ councilId: string; escrows: number }>> {
  const configured = configuredCouncils().map((c) => c.id);
  const groups = await db.councilEscrow.groupBy({ by: ['councilId'], where: { councilId: { notIn: configured } }, _count: { _all: true } });

  return groups.map((g) => ({ councilId: g.councilId, escrows: g._count._all }));
}

/**
 * A custodian's new or disabled identity changes what their council's proposal
 * must pin: sync at once, or their proposal would name a key they no longer hold
 * until the next hourly run. Retried when another instance holds the lock, since
 * its run may have read before our commit.
 */
export function syncCouncilsAfterIdentityChange(userId: string, log: FastifyBaseLogger): void {
  if (!configuredCouncils().some((council) => council.custodians.some((custodian) => custodian.userId === userId))) return;

  void (async () => {
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, 2000));
      if (await syncConfiguredCouncils(log)) return;
    }
  })().catch((err: unknown) => log.warn({ err }, 'recovery council sync after an identity change failed'));
}

/** Email the user of a request that became ready, once (`claimReadyNotice`); the email itself is not awaited. */
export async function notifyReadyRequest(requestId: string, log: FastifyBaseLogger): Promise<void> {
  const ready = await claimReadyNotice(requestId);
  if (!ready) return;

  const recipient = await emergencyRecipient(ready.userId);
  if (recipient)
    sendCouncilRecoveryReady({ recipient: recipient.email, locale: recipient.locale, council: await councilLabel(ready.councilId) }).catch(
      (err: unknown) => log.error({ err }, 'recovery council email failed: recovery ready')
    );
}

/**
 * Announce a request at the end of its cooldown. The timer lives in this process
 * only: boot arms it again for every waiting request and the hourly run catches
 * any that slipped through, the claim keeping it to one email.
 */
export function scheduleReadyNotice(requestId: string, releaseNotBefore: Date, log: FastifyBaseLogger): void {
  setTimeout(
    () => void notifyReadyRequest(requestId, log).catch((err: unknown) => log.warn({ err }, 'recovery ready notice failed')),
    Math.max(0, releaseNotBefore.getTime() - Date.now())
  ).unref();
}

/** Sync now, then hourly, for the life of the process; closed requests are purged on the way. */
export function startCouncilSync(log: FastifyBaseLogger): void {
  void unconfiguredCouncilsWithEscrows()
    .then((orphans) => {
      for (const { councilId, escrows } of orphans) {
        log.warn(
          `Recovery council "${councilId}" is no longer in RECOVERY_COUNCILS but still holds ${escrows} escrow(s): its users stay on it until they move to a council that covers them. Restore the entry if it was removed by mistake; to rename a council, change its label, never its id.`
        );
      }
    })
    .catch((err: unknown) => log.warn({ err }, 'recovery council check failed'));

  const run = async () => {
    try {
      await syncConfiguredCouncils(log);
      for (const requestId of await readyNoticeCandidates()) await notifyReadyRequest(requestId, log);
      // Escrows a resharing held back, whose sub-shares are all in.
      for (const { id } of await prisma.councilReshareSession.findMany({ where: { status: 'open' }, select: { id: true } }))
        await moveCompleteEscrows(id);
      await prisma.councilRequest.deleteMany({
        where: {
          status: { in: ['completed', 'refused', 'aborted', 'expired'] },
          closedAt: { lt: new Date(Date.now() - CLOSED_REQUEST_RETENTION_MS) },
        },
      });
    } catch (err) {
      log.warn({ err }, 'recovery council sync failed');
    }
  };

  void waitingReadyNotices()
    .then((waiting) => {
      for (const { id, releaseNotBefore } of waiting) scheduleReadyNotice(id, releaseNotBefore, log);
    })
    .catch((err: unknown) => log.warn({ err }, 'recovery ready notices failed'));

  void run();
  setInterval(() => void run(), SYNC_INTERVAL_MS).unref();
}
