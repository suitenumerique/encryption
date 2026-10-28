/**
 * What happens to capsules, sub-shares, commitments and transfer keys (architecture.md
 * F.4): a roster version taking effect, a resharing moving an escrow, a
 * resharing closed. Every deletion of those rows lives here.
 *
 * The rule they all follow: a reshared capsule opens only through the
 * sub-shares, commitments and transfer keys of its session (`capsule.sessionId`),
 * so those rows are never deleted while a capsule points at them. Only the rows
 * of escrows a session has not moved yet may go.
 */
import { uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { decodeCommitments, encodeCommitments, equalPoints, sumCommitments } from '@encryption/src/crypto/shamir';
import { prisma } from '@encryption/src/prisma/client';
import {
  ROSTER_INCLUDE,
  type RosterVersionRow,
  type Tx,
  councilHead,
  councilProposal,
  proposalProgress,
  serializable,
} from '@encryption/src/server/council-core';
import type { CouncilCapsuleWire } from '@encryption/src/shared/schemas/recovery-council';

const LIVE_REQUEST = { status: { in: ['open' as const, 'released' as const] } };

type Session = { id: string; councilId: string; sourceRosterVersionId: string };

/**
 * Close a resharing: the sub-shares and commitments of the escrows it did not
 * move are deleted, and its transfer keys too when it moved none. The escrows it
 * moved keep everything their capsules open with.
 */
async function closeSession(tx: Tx, session: Session, status: 'completed' | 'cancelled'): Promise<void> {
  const unmoved = { escrow: { rosterVersionId: session.sourceRosterVersionId } };
  await tx.councilSubShare.deleteMany({ where: { sessionId: session.id, ...unmoved } });
  await tx.councilReshareCommitment.deleteMany({ where: { sessionId: session.id, ...unmoved } });

  if ((await tx.councilCapsule.count({ where: { sessionId: session.id } })) === 0)
    await tx.councilReshareKey.deleteMany({ where: { sessionId: session.id } });

  await tx.councilReshareSession.update({ where: { id: session.id }, data: { status, closedAt: new Date() } });
}

/** A custodian stops a resharing. Escrows already moved stay moved; the others stay on the source version. */
export async function cancelReshareSession(sessionId: string): Promise<boolean> {
  return serializable(async (tx) => {
    const session = await tx.councilReshareSession.findUnique({ where: { id: sessionId } });
    if (!session || session.status !== 'open') return false;

    await closeSession(tx, session, 'cancelled');

    return true;
  });
}

/**
 * Make a fully signed proposal the head. In the same transaction, the capsules
 * of every slot the new version no longer holds with the same key are deleted
 * (a removed custodian can no longer obtain a share), and an open resharing,
 * which targeted the previous head, is closed.
 */
export async function activateIfReady(councilId: string): Promise<RosterVersionRow | null> {
  return serializable(async (tx) => {
    const proposal = await councilProposal(councilId, tx);
    if (!proposal) return null;

    const head = await councilHead(councilId, tx);
    if (!proposalProgress(proposal, head).ready) return null;

    if (head) await tx.councilRosterVersion.update({ where: { id: head.id }, data: { status: 'superseded' } });

    const activated = await tx.councilRosterVersion.update({
      where: { id: proposal.id },
      data: { status: 'active', activatedAt: new Date() },
      include: ROSTER_INCLUDE,
    });

    const kept = activated.members.map((m) => ({ slot: m.slot, identityId: m.identityId }));
    await tx.councilCapsule.deleteMany({ where: { escrow: { councilId }, NOT: { OR: kept } } });
    // Sub-shares sealed for a slot the new version no longer holds: the capsules
    // they fed were just deleted, and nobody may add them up any more.
    await tx.councilSubShare.deleteMany({ where: { escrow: { councilId }, recipientSlot: { notIn: kept.map((k) => k.slot) } } });

    const open = await tx.councilReshareSession.findMany({ where: { councilId, status: 'open' } });
    for (const session of open) {
      const moved = await tx.councilCapsule.count({ where: { sessionId: session.id } });
      await closeSession(tx, session, moved > 0 ? 'completed' : 'cancelled');
    }

    return activated;
  });
}

/** Escrows a session still has to move, and how many of them this helper has not sealed sub-shares for. */
export async function reshareProgress(sessionId: string, mySlot: number): Promise<{ remaining: number; remainingForMe: number }> {
  const session = await prisma.councilReshareSession.findUniqueOrThrow({ where: { id: sessionId } });
  const pending = await prisma.councilEscrow.findMany({
    where: { councilId: session.councilId, rosterVersionId: session.sourceRosterVersionId },
    select: { id: true, generation: true, capsules: { select: { slot: true, generation: true } } },
  });
  const eligible = pending.filter((e) =>
    session.helperSlots.every((slot) => e.capsules.some((c) => c.slot === slot && c.generation === e.generation))
  );
  const doneByMe = new Set(
    (
      await prisma.councilSubShare.findMany({
        where: { sessionId, helperSlot: mySlot },
        distinct: ['escrowId'],
        select: { escrowId: true },
      })
    ).map((s) => s.escrowId)
  );

  return {
    remaining: eligible.length,
    remainingForMe: session.helperSlots.includes(mySlot) ? eligible.filter((e) => !doneByMe.has(e.id)).length : 0,
  };
}

/**
 * Move one escrow to the session's target once every helper sealed its
 * sub-shares for it. An escrow with a recovery in progress waits: the shares
 * already handed over belong to its current split (afterRequestClosed moves it).
 */
export async function moveEscrowIfComplete(sessionId: string, escrowId: string): Promise<boolean> {
  return serializable(async (tx) => {
    const session = await tx.councilReshareSession.findUniqueOrThrow({
      where: { id: sessionId },
      include: { targetRosterVersion: { include: { members: true } } },
    });
    if (session.status !== 'open') return false;

    const escrow = await tx.councilEscrow.findUnique({ where: { id: escrowId } });
    if (!escrow || escrow.rosterVersionId !== session.sourceRosterVersionId) return false;
    if ((await tx.councilRequest.count({ where: { escrowId, ...LIVE_REQUEST } })) > 0) return false;

    const target = session.targetRosterVersion;
    const count = await tx.councilSubShare.count({ where: { sessionId, escrowId } });
    if (count < session.helperSlots.length * target.members.length) return false;

    const perHelper = await tx.councilReshareCommitment.findMany({ where: { sessionId, escrowId } });
    if (perHelper.length < session.helperSlots.length) return false;

    // Each helper's constant term was checked on arrival; their sum is then the
    // constant term of the current split, which this asserts once more.
    const commitments = sumCommitments(perHelper.map((c) => decodeCommitments(new Uint8Array(c.commitments))));
    if (!equalPoints(commitments[0], decodeCommitments(new Uint8Array(escrow.commitments))[0])) return false;

    const generation = escrow.generation + 1;
    await tx.councilCapsule.deleteMany({ where: { escrowId } });
    // The sub-shares of earlier resharings fed the capsules just deleted.
    await tx.councilSubShare.deleteMany({ where: { escrowId, sessionId: { not: sessionId } } });
    await tx.councilReshareCommitment.deleteMany({ where: { escrowId, sessionId: { not: sessionId } } });
    await tx.councilCapsule.createMany({
      data: target.members.map((m) => ({ escrowId, generation, slot: m.slot, identityId: m.identityId, sessionId })),
    });
    await tx.councilEscrow.update({
      where: { id: escrowId },
      data: { rosterVersionId: target.id, threshold: target.threshold, generation, commitments: Buffer.from(encodeCommitments(commitments)) },
    });

    return true;
  });
}

/**
 * Move every escrow of the session that has all its sub-shares and is still on
 * the source (a move that lost a race, or waited for a recovery), then close the
 * session when nothing is left. Returns how many moved.
 */
export async function moveCompleteEscrows(sessionId: string): Promise<number> {
  const session = await prisma.councilReshareSession.findUnique({
    where: { id: sessionId },
    include: { targetRosterVersion: { include: { members: true } } },
  });
  if (!session || session.status !== 'open') return 0;

  const needed = session.helperSlots.length * session.targetRosterVersion.members.length;
  const counts = await prisma.councilSubShare.groupBy({
    by: ['escrowId'],
    where: { sessionId, escrow: { rosterVersionId: session.sourceRosterVersionId } },
    _count: { _all: true },
  });

  let moved = 0;
  for (const { escrowId, _count } of counts) {
    if (_count._all >= needed && (await moveEscrowIfComplete(sessionId, escrowId))) moved++;
  }

  if ((await reshareProgress(sessionId, 0)).remaining === 0) {
    await prisma.councilReshareSession.updateMany({ where: { id: sessionId, status: 'open' }, data: { status: 'completed', closedAt: new Date() } });
  }

  return moved;
}

/** A recovery ended: an escrow a resharing was holding back can move now. */
export async function afterRequestClosed(escrowId: string): Promise<void> {
  const escrow = await prisma.councilEscrow.findUnique({ where: { id: escrowId } });
  if (!escrow) return;

  const session = await prisma.councilReshareSession.findFirst({
    where: { councilId: escrow.councilId, status: 'open', sourceRosterVersionId: escrow.rosterVersionId },
  });
  if (session) await moveCompleteEscrows(session.id);
}

/**
 * A capsule as the custodian's vault receives it, resolving a resharing's
 * sub-shares and signed transfer keys. A reshared capsule missing any of them can
 * never open: it is marked invalid, so the escrow's health stops counting it.
 */
export async function capsuleWire(
  capsule: { id: string; slot: number; generation: number; wrappedShare: string | null; sessionId: string | null },
  escrowId: string
): Promise<CouncilCapsuleWire> {
  if (capsule.wrappedShare) return { kind: 'direct', generation: capsule.generation, slot: capsule.slot, wrapped_share: capsule.wrappedShare };

  const session = await prisma.councilReshareSession.findUniqueOrThrow({
    where: { id: capsule.sessionId! },
    include: { sourceRosterVersion: { include: { members: { include: { identity: true } } } }, targetRosterVersion: true },
  });
  const [keys, subShares, commitments] = await Promise.all([
    prisma.councilReshareKey.findMany({ where: { sessionId: session.id, recipientSlot: capsule.slot } }),
    prisma.councilSubShare.findMany({ where: { sessionId: session.id, escrowId, recipientSlot: capsule.slot } }),
    prisma.councilReshareCommitment.findMany({ where: { sessionId: session.id, escrowId } }),
  ]);

  const helpers = session.helperSlots.map((helperSlot) => ({
    helperSlot,
    key: keys.find((k) => k.helperSlot === helperSlot),
    subShare: subShares.find((s) => s.helperSlot === helperSlot),
    committed: commitments.find((c) => c.helperSlot === helperSlot),
    helper: session.sourceRosterVersion.members.find((m) => m.slot === helperSlot),
  }));

  if (helpers.some((h) => !h.key || !h.subShare || !h.committed || !h.helper)) {
    await prisma.councilCapsule.update({ where: { id: capsule.id }, data: { invalid: true } });
    throw new Error(`Reshared capsule ${capsule.id} lost the rows it opens with`);
  }

  return {
    kind: 'reshared',
    generation: capsule.generation,
    slot: capsule.slot,
    session_id: session.id,
    escrow_id: escrowId,
    target_roster_version: session.targetRosterVersion.version,
    helpers: helpers.map(({ helperSlot, key, subShare, committed, helper }) => ({
      helper_slot: helperSlot,
      helper_identity_public_key: uint8ToBase64(new Uint8Array(helper!.identity.signaturePublicKey)),
      wrapped_transfer_key: key!.wrappedTransferKey,
      binding_signature: uint8ToBase64(new Uint8Array(key!.signature)),
      sealed_sub_share: subShare!.sealed,
      commitments: uint8ToBase64(new Uint8Array(committed!.commitments)),
      commitments_signature: uint8ToBase64(new Uint8Array(committed!.signature)),
    })),
  };
}
