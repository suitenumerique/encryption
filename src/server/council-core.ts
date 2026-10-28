/**
 * Recovery council state on the server (shamir.md §9-11): the roster chain the
 * custodians sign, the change the configuration proposes, and the health of
 * every escrow split over it.
 *
 * The configuration (RECOVERY_COUNCILS) is only ever compared with the signed
 * head: a difference becomes a proposed version, which takes effect only once
 * the custodians signed it. Nothing here deletes a council, a version or an
 * escrow because the configuration changed or disappeared; the only deletion is
 * of the capsules of a custodian a SIGNED version removed or re-keyed.
 */
import { type RosterRecord, rosterHash } from '@encryption/src/crypto/council';
import { uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import type { Prisma } from '@encryption/src/generated/prisma/client';
import { prisma } from '@encryption/src/prisma/client';
import type { RecoveryCouncilConfig } from '@encryption/src/server/recovery-councils';
import { userFullName } from '@encryption/src/server/user-name';
import type { CouncilEscrowRecordWire, RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';

export const ROSTER_INCLUDE = {
  members: { include: { identity: true, user: true }, orderBy: { slot: 'asc' } },
  signatures: { include: { identity: true } },
} satisfies Prisma.CouncilRosterVersionInclude;

export type RosterVersionRow = Prisma.CouncilRosterVersionGetPayload<{ include: typeof ROSTER_INCLUDE }>;

type Tx = Prisma.TransactionClient;

export function rosterRecordOf(row: RosterVersionRow): RosterRecord {
  return {
    councilId: row.councilId,
    version: row.version,
    threshold: row.threshold,
    previousRosterHash: new Uint8Array(row.previousRosterHash),
    members: row.members.map((m) => ({ slot: m.slot, userId: m.userId, identityPublicKeyWire: new Uint8Array(m.identity.signaturePublicKey) })),
  };
}

export function rosterVersionWire(row: RosterVersionRow): RosterVersionWire {
  return {
    version: row.version,
    threshold: row.threshold,
    previous_roster_hash: uint8ToBase64(new Uint8Array(row.previousRosterHash)),
    members: row.members.map((m) => ({
      slot: m.slot,
      user_id: m.userId,
      identity_public_key: uint8ToBase64(new Uint8Array(m.identity.signaturePublicKey)),
      name: userFullName(m.user) ?? m.user.email,
    })),
    signatures: row.signatures.map((s) => ({
      identity_public_key: uint8ToBase64(new Uint8Array(s.identity.signaturePublicKey)),
      signature: uint8ToBase64(new Uint8Array(s.signature)),
    })),
  };
}

export function councilHead(councilId: string, db: Tx | typeof prisma = prisma): Promise<RosterVersionRow | null> {
  return db.councilRosterVersion.findFirst({ where: { councilId, status: 'active' }, include: ROSTER_INCLUDE });
}

export function councilProposal(councilId: string, db: Tx | typeof prisma = prisma): Promise<RosterVersionRow | null> {
  return db.councilRosterVersion.findFirst({ where: { councilId, status: 'proposed' }, include: ROSTER_INCLUDE });
}

/** The signed chain users and custodians verify: every version that was ever in force, oldest first. */
export async function councilChain(councilId: string): Promise<RosterVersionRow[]> {
  return prisma.councilRosterVersion.findMany({
    where: { councilId, status: { in: ['active', 'superseded'] } },
    include: ROSTER_INCLUDE,
    orderBy: { version: 'asc' },
  });
}

// ----- What the configuration asks for --------------------------------------

export type BlockedCustodianReason = 'unknown-user' | 'email-mismatch' | 'not-onboarded';

export interface BlockedCustodian {
  userId: string;
  email: string;
  reason: BlockedCustodianReason;
}

/** A configured custodian can sit in a roster once they have an identity, an encryption key and a vault. */
async function custodianIdentity(userId: string, email: string): Promise<{ identityId: string } | { blocked: BlockedCustodianReason }> {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return { blocked: 'unknown-user' };
  // The email guards against a mistyped user id: a council never names someone
  // the operator did not mean.
  if (user.email.trim().toLowerCase() !== email) return { blocked: 'email-mismatch' };

  const [identity, key, vault] = await Promise.all([
    prisma.identity.findFirst({ where: { userId, disabledAt: null }, orderBy: { generation: 'desc' } }),
    prisma.encryptionKey.findFirst({ where: { userId, disabledAt: null } }),
    prisma.vaultKeyring.findFirst({ where: { userId, disabledAt: null } }),
  ]);
  if (!identity || !key || !vault) return { blocked: 'not-onboarded' };

  return { identityId: identity.id };
}

export interface CouncilSyncResult {
  blocked: BlockedCustodian[];
  proposal: RosterVersionRow | null;
}

/**
 * Bring the proposed version of one council in line with the configuration and
 * with its custodians' current identities (a custodian who started over needs a
 * version with their new key). No-op when the head already matches.
 *
 * A proposal is replaced, signatures included, as soon as what it says differs
 * from what is asked: a signature covers one exact roster.
 */
export async function syncCouncilProposal(config: RecoveryCouncilConfig): Promise<CouncilSyncResult> {
  const desired: Array<{ userId: string; identityId: string }> = [];
  const blocked: BlockedCustodian[] = [];

  for (const custodian of config.custodians) {
    const outcome = await custodianIdentity(custodian.userId, custodian.email);

    if ('blocked' in outcome) blocked.push({ userId: custodian.userId, email: custodian.email, reason: outcome.blocked });
    else desired.push({ userId: custodian.userId, identityId: outcome.identityId });
  }

  const head = await councilHead(config.id);
  const existing = await councilProposal(config.id);

  // Someone the configuration names cannot be pinned yet: nothing to sign. A
  // proposal made from an older configuration no longer says what is asked.
  if (blocked.length > 0) {
    if (existing) await prisma.councilRosterVersion.delete({ where: { id: existing.id } });

    return { blocked, proposal: null };
  }

  const sameAs = (row: RosterVersionRow | null) =>
    row !== null &&
    row.threshold === config.threshold &&
    row.members.length === desired.length &&
    desired.every((d) => row.members.some((m) => m.userId === d.userId && m.identityId === d.identityId));

  if (sameAs(head)) {
    if (existing) await prisma.councilRosterVersion.delete({ where: { id: existing.id } });

    return { blocked, proposal: null };
  }

  if (sameAs(existing)) return { blocked, proposal: existing };

  const proposal = await prisma.$transaction(
    async (tx) => {
      if (existing) await tx.councilRosterVersion.delete({ where: { id: existing.id } });

      // A slot is never given again: a newcomer, or a custodian with a new key,
      // takes the next number never used in this council.
      const usedSlots = await tx.councilRosterMember.findMany({ where: { rosterVersion: { councilId: config.id } }, select: { slot: true } });
      let nextSlot = usedSlots.reduce((max, m) => Math.max(max, m.slot), 0) + 1;

      const members = desired.map((d) => {
        const kept = head?.members.find((m) => m.userId === d.userId && m.identityId === d.identityId);

        return { userId: d.userId, identityId: d.identityId, slot: kept ? kept.slot : nextSlot++ };
      });

      const identities = await tx.identity.findMany({ where: { id: { in: members.map((m) => m.identityId) } } });
      const wireOf = new Map(identities.map((i) => [i.id, new Uint8Array(i.signaturePublicKey)]));

      const previousRosterHash = head ? new Uint8Array(head.rosterHash) : new Uint8Array(0);
      const record: RosterRecord = {
        councilId: config.id,
        version: (head?.version ?? 0) + 1,
        threshold: config.threshold,
        previousRosterHash,
        members: members.map((m) => ({ slot: m.slot, userId: m.userId, identityPublicKeyWire: wireOf.get(m.identityId)! })),
      };

      return tx.councilRosterVersion.create({
        data: {
          councilId: config.id,
          version: record.version,
          threshold: record.threshold,
          status: 'proposed',
          previousRosterHash: Buffer.from(previousRosterHash),
          rosterHash: Buffer.from(await rosterHash(record)),
          members: { create: members },
        },
        include: ROSTER_INCLUDE,
      });
    },
    { isolationLevel: 'Serializable' }
  );

  return { blocked, proposal };
}

// ----- Signatures and activation ---------------------------------------------

export interface ProposalProgress {
  /** Signatures still missing from custodians of the head (0 for a first version). */
  quorumMissing: number;
  /** Members who must vouch for their own key and have not yet: everyone in a first version, newcomers after. */
  pendingMembers: Array<{ userId: string; slot: number }>;
  ready: boolean;
}

function isNewcomer(member: RosterVersionRow['members'][number], head: RosterVersionRow | null): boolean {
  return !head?.members.some((m) => m.slot === member.slot && m.userId === member.userId && m.identityId === member.identityId);
}

/** Whether a proposal has what it needs to take effect (signatures were verified when written). */
export function proposalProgress(proposal: RosterVersionRow, head: RosterVersionRow | null): ProposalProgress {
  const signedBy = new Set(proposal.signatures.map((s) => s.identityId));
  const pendingMembers = proposal.members
    .filter((m) => isNewcomer(m, head) && !signedBy.has(m.identityId))
    .map((m) => ({ userId: m.userId, slot: m.slot }));
  const quorum = head ? head.members.filter((m) => signedBy.has(m.identityId)).length : 0;
  const quorumMissing = head ? Math.max(0, head.threshold - quorum) : 0;

  return { quorumMissing, pendingMembers, ready: quorumMissing === 0 && pendingMembers.length === 0 };
}

/**
 * Make a fully signed proposal the head. In the same transaction, the capsules
 * of every slot the new version no longer holds with the same key are deleted:
 * a removed custodian can no longer obtain a share, and a custodian who started
 * over holds nothing their new key opens anyway.
 */
export async function activateIfReady(councilId: string): Promise<RosterVersionRow | null> {
  return prisma.$transaction(
    async (tx) => {
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
      // Sub-shares a resharing sealed for a slot the new version no longer holds:
      // nobody may add them up any more.
      await tx.councilSubShare.deleteMany({ where: { escrow: { councilId }, recipientSlot: { notIn: kept.map((k) => k.slot) } } });

      // A resharing in progress targeted the previous head: its sub-shares would
      // land on a roster no longer in force.
      const stale = await tx.councilReshareSession.findMany({ where: { councilId, status: 'open' }, select: { id: true } });
      if (stale.length > 0) {
        const ids = stale.map((s) => s.id);
        await tx.councilSubShare.deleteMany({ where: { sessionId: { in: ids } } });
        await tx.councilReshareKey.deleteMany({ where: { sessionId: { in: ids } } });
        await tx.councilReshareSession.updateMany({ where: { id: { in: ids } }, data: { status: 'cancelled', closedAt: new Date() } });
      }

      return activated;
    },
    { isolationLevel: 'Serializable' }
  );
}

// ----- Health -----------------------------------------------------------------

export type EscrowHealthStatus = 'ok' | 'at-risk' | 'lost';

export interface EscrowHealth {
  live: number;
  threshold: number;
  status: EscrowHealthStatus;
  /** Split over an older version than the head: custodians can reshare it. */
  outdated: boolean;
}

/**
 * How many custodians of the head can still hand over their share of this
 * escrow. Computed from the SIGNED head and the custodians' current identities,
 * never from the configuration, so a broken or empty variable never makes an
 * escrow look lost.
 */
export function escrowHealth(
  escrow: {
    rosterVersionId: string;
    threshold: number;
    generation: number;
    capsules: Array<{ slot: number; identityId: string; generation: number }>;
  },
  head: RosterVersionRow | null,
  activeIdentityIds: Set<string>
): EscrowHealth {
  const live = escrow.capsules.filter(
    (c) =>
      c.generation === escrow.generation &&
      activeIdentityIds.has(c.identityId) &&
      (head?.members.some((m) => m.slot === c.slot && m.identityId === c.identityId) ?? false)
  ).length;

  const status: EscrowHealthStatus = live < escrow.threshold ? 'lost' : live === escrow.threshold ? 'at-risk' : 'ok';

  return { live, threshold: escrow.threshold, status, outdated: head !== null && escrow.rosterVersionId !== head.id };
}

export async function activeIdentityIdsOf(identityIds: string[]): Promise<Set<string>> {
  const rows = await prisma.identity.findMany({ where: { id: { in: identityIds }, disabledAt: null }, select: { id: true } });

  return new Set(rows.map((r) => r.id));
}

// ----- Escrow record ------------------------------------------------------------

export interface SignedShareEntry {
  slot: number;
  capsule_hash: string;
}

export function escrowRecordWire(
  escrow: {
    councilId: string;
    signedThreshold: number;
    signedShares: Prisma.JsonValue;
    signedCommitments: Uint8Array;
    secretCommitment: Uint8Array;
    escrowSignature: Uint8Array;
    escrowCreatedAt: Date;
    signedRosterVersion: { version: number; rosterHash: Uint8Array };
  },
  credentialAuthPublicKeyHash: Uint8Array
): CouncilEscrowRecordWire {
  return {
    council_id: escrow.councilId,
    roster_version: escrow.signedRosterVersion.version,
    roster_hash: uint8ToBase64(new Uint8Array(escrow.signedRosterVersion.rosterHash)),
    threshold: escrow.signedThreshold,
    escrow_created_at_millis: escrow.escrowCreatedAt.getTime(),
    credential_auth_public_key_hash: uint8ToBase64(credentialAuthPublicKeyHash),
    secret_commitment: uint8ToBase64(new Uint8Array(escrow.secretCommitment)),
    share_commitments: uint8ToBase64(new Uint8Array(escrow.signedCommitments)),
    shares: escrow.signedShares as unknown as SignedShareEntry[],
    escrow_signature: uint8ToBase64(new Uint8Array(escrow.escrowSignature)),
  };
}
