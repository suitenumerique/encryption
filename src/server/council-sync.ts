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
import { configuredCouncils, councilHead, syncCouncilProposal } from '@encryption/src/server/council-core';
import { sendCouncilRosterToSign } from '@encryption/src/server/email/council';
import { env } from '@encryption/src/server/env';
import { emergencyRecipient } from '@encryption/src/server/routes/emergency-core';

const SYNC_INTERVAL_MS = 5 * 60 * 1000;
// Arbitrary, fixed: the key of the advisory lock only council syncs take.
const SYNC_LOCK_KEY = 7_200_001;

/** Sync every configured council once. Returns false when another instance holds the lock. */
export async function syncConfiguredCouncils(log: FastifyBaseLogger): Promise<boolean> {
  const toNotify: Array<{ councilId: string; label: string; userIds: string[] }> = [];

  const locked = await prisma.$transaction(
    async (tx) => {
      const [{ locked }] = await tx.$queryRaw<Array<{ locked: boolean }>>`SELECT pg_try_advisory_xact_lock(${SYNC_LOCK_KEY}) AS locked`;
      if (!locked) return false;

      for (const config of configuredCouncils()) {
        const result = await syncCouncilProposal(config, tx);
        if (!result.proposal) continue;

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

  return locked;
}

// A closed request is kept a while for the daily limit on asking, then purged.
const CLOSED_REQUEST_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

/** Sync now, then every few minutes, for the life of the process; closed requests are purged on the way. */
/**
 * Councils that still hold escrows but are no longer in the configuration. A
 * council is its `id`: renaming one starts a new council beside the old, whose
 * users stay on it, so a rename or a removal by mistake must not go unnoticed.
 */
export async function unconfiguredCouncilsWithEscrows(): Promise<Array<{ councilId: string; escrows: number }>> {
  const configured = configuredCouncils().map((c) => c.id);
  const groups = await prisma.councilEscrow.groupBy({ by: ['councilId'], where: { councilId: { notIn: configured } }, _count: { _all: true } });

  return groups.map((g) => ({ councilId: g.councilId, escrows: g._count._all }));
}

export function startCouncilSync(log: FastifyBaseLogger): void {
  void unconfiguredCouncilsWithEscrows()
    .then((orphans) => {
      for (const { councilId, escrows } of orphans) {
        log.warn(
          `Recovery council "${councilId}" is no longer in RECOVERY_COUNCILS but still holds ${escrows} escrow(s): its users stay on it. A council id is never renamed (change its label instead); restore the entry if it was removed by mistake.`
        );
      }
    })
    .catch((err: unknown) => log.warn({ err }, 'recovery council check failed'));

  const run = async () => {
    try {
      if (configuredCouncils().length > 0) await syncConfiguredCouncils(log);
      await prisma.councilRequest.deleteMany({ where: { status: 'aborted', closedAt: { lt: new Date(Date.now() - CLOSED_REQUEST_RETENTION_MS) } } });
    } catch (err) {
      log.warn({ err }, 'recovery council sync failed');
    }
  };

  void run();
  setInterval(() => void run(), SYNC_INTERVAL_MS).unref();
}
