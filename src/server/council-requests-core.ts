/**
 * A recovery request's state (architecture.md F.3): what stage it is at, derived from
 * its contributions, and the transitions (release, expiry, refusal, abort), each
 * under a row lock on the request so a contribution and a transition never
 * interleave.
 */
import { z } from 'zod';

import type { CouncilRequest, Prisma } from '@encryption/src/generated/prisma/client';
import { prisma } from '@encryption/src/prisma/client';
import { type EscrowHealth, type Tx, activeIdentityIdsOf, councilHead, escrowHealth, rawTable } from '@encryption/src/server/council-core';
import { afterRequestClosed } from '@encryption/src/server/council-reshare-core';

// How a request looks from the outside. Between `open` and `released`, the
// progress is derived from the contributions: first the meeting (one share
// handed over in person, the attestation every remote vault requires), then the
// remote approvals. The locked-out user only ever sees "go and see one of these
// people", then "in progress", never a count.
export const RequestStageSchema = z.enum(['collecting', 'awaiting_meeting', 'cooldown', 'released', 'completed', 'aborted', 'expired']);
export type RequestStage = z.infer<typeof RequestStageSchema>;

export const EscrowHealthSchema = z.object({
  live: z.number().int().nonnegative(),
  threshold: z.number().int().positive(),
  status: z.enum(['ok', 'at-risk', 'lost']),
  outdated: z.boolean(),
});

export function healthWire(health: EscrowHealth) {
  return { live: health.live, threshold: health.threshold, status: health.status, outdated: health.outdated };
}

export type EscrowWithParts = Prisma.CouncilEscrowGetPayload<{
  include: { capsules: true; credential: { include: { vault: true } }; signedRosterVersion: true };
}>;

/** The escrow a recovery request of this user is about: the one on their current vault, else their latest. */
export async function escrowForRecovery(userId: string): Promise<EscrowWithParts | null> {
  const escrows = await prisma.councilEscrow.findMany({
    where: { userId },
    include: { capsules: true, credential: { include: { vault: true } }, signedRosterVersion: true },
    orderBy: { createdAt: 'desc' },
  });

  return escrows.find((e) => e.credential.vault.disabledAt === null) ?? escrows[0] ?? null;
}

export async function healthOf(escrow: EscrowWithParts | Prisma.CouncilEscrowGetPayload<{ include: { capsules: true } }>): Promise<EscrowHealth> {
  const head = await councilHead(escrow.councilId);
  const active = await activeIdentityIdsOf(escrow.capsules.map((c) => c.identityId));

  return escrowHealth(escrow, head, active);
}

/** Slots whose current share can still be handed over: in the head with the same, still active key. */
export async function liveSlots(escrow: {
  councilId: string;
  generation: number;
  capsules: Array<{ slot: number; identityId: string; generation: number; invalid: boolean }>;
}) {
  const head = await councilHead(escrow.councilId);
  const active = await activeIdentityIdsOf(escrow.capsules.map((c) => c.identityId));

  return escrow.capsules
    .filter(
      (c) =>
        c.generation === escrow.generation &&
        !c.invalid &&
        active.has(c.identityId) &&
        (head?.members.some((m) => m.slot === c.slot && m.identityId === c.identityId) ?? false)
    )
    .map((c) => ({ slot: c.slot, member: head!.members.find((m) => m.slot === c.slot)! }));
}

export interface RequestFacts {
  request: CouncilRequest;
  threshold: number;
  /** Contributions that count: from a custodian still in the head with the key they signed with. */
  contributions: Array<{ slot: number; inPerson: boolean }>;
}

export function requestStage({ request, threshold, contributions }: RequestFacts, nowMs: number): RequestStage {
  if (request.status === 'completed') return 'completed';
  if (request.status === 'aborted') return 'aborted';
  if (request.expiresAt.getTime() <= nowMs) return 'expired';
  if (request.status === 'released') return 'released';

  const inPerson = contributions.some((c) => c.inPerson);

  if (!inPerson) return 'awaiting_meeting';
  if (contributions.length >= threshold) return request.releaseNotBefore.getTime() <= nowMs ? 'released' : 'cooldown';

  return 'collecting';
}

/** Lock the request row until the transaction ends. False when there is no such request. */
export async function lockRequest(tx: Tx, requestId: string): Promise<boolean> {
  const rows = await tx.$queryRaw<Array<{ id: string }>>`SELECT id FROM ${rawTable('council_requests')} WHERE id = ${requestId}::uuid FOR UPDATE`;

  return rows.length > 0;
}

async function closeLocked(tx: Tx, requestId: string, nowMs: number): Promise<boolean> {
  await tx.councilContribution.deleteMany({ where: { requestId } });
  const closed = await tx.councilRequest.updateMany({
    where: { id: requestId, status: { in: ['open', 'released'] } },
    data: { status: 'aborted', closedAt: new Date(nowMs) },
  });

  return closed.count > 0;
}

/**
 * Bring a locked request's stored status in line with its facts: the release
 * (once the shares are in and the cooldown elapsed) and the expiry are both
 * lazy, like the wait arithmetic of trusted contacts, so no job has to run for
 * them to hold. The caller holds the lock (lockRequest).
 */
export async function settleLocked(tx: Tx, requestId: string, nowMs: number): Promise<{ facts: RequestFacts; stage: RequestStage; closed: boolean }> {
  const request = await tx.councilRequest.findUniqueOrThrow({ where: { id: requestId }, include: { contributions: true, escrow: true } });
  const head = await councilHead(request.escrow.councilId, tx);

  const facts: RequestFacts = {
    request,
    threshold: request.escrow.threshold,
    contributions: request.contributions
      .filter((c) => head?.members.some((m) => m.slot === c.slot && m.identityId === c.custodianIdentityId))
      .map((c) => ({ slot: c.slot, inPerson: c.inPerson })),
  };
  const stage = requestStage(facts, nowMs);
  let closed = false;

  if (stage === 'expired' && (request.status === 'open' || request.status === 'released')) {
    closed = await closeLocked(tx, requestId, nowMs);
  } else if (stage === 'released' && request.status === 'open') {
    facts.request = await tx.councilRequest.update({ where: { id: requestId }, data: { status: 'released', releasedAt: new Date(nowMs) } });
  }

  return { facts, stage, closed };
}

/** settleLocked in a transaction of its own. Null when there is no such request. */
export async function settleRequest(requestId: string, nowMs: number): Promise<{ facts: RequestFacts; stage: RequestStage } | null> {
  const settled = await prisma.$transaction(async (tx) => ((await lockRequest(tx, requestId)) ? settleLocked(tx, requestId, nowMs) : null));
  if (settled?.closed) await afterRequestClosed(settled.facts.request.escrowId);

  return settled;
}

/** Stop a request (refused by its user, aborted by a custodian): its shares are discarded. True when it was live. */
export async function closeRequest(requestId: string): Promise<boolean> {
  const closed = await prisma.$transaction(async (tx) => (await lockRequest(tx, requestId)) && closeLocked(tx, requestId, Date.now()));

  if (closed) {
    const row = await prisma.councilRequest.findUnique({ where: { id: requestId }, select: { escrowId: true } });
    if (row) await afterRequestClosed(row.escrowId);
  }

  return closed;
}

export async function openRequestOf(userId: string): Promise<CouncilRequest | null> {
  const now = Date.now();
  const candidates = await prisma.councilRequest.findMany({
    where: { userId, status: { in: ['open', 'released'] } },
    orderBy: { createdAt: 'desc' },
  });

  for (const candidate of candidates) {
    const settled = await settleRequest(candidate.id, now);
    if (settled && settled.stage !== 'expired') return settled.facts.request;
  }

  return null;
}
