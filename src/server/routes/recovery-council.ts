import type { FastifyBaseLogger, FastifyInstance, FastifyReply } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { createHash } from 'node:crypto';
import { z } from 'zod';

import {
  type ContributionRecord,
  type CouncilEscrowRecord,
  type ReshareKeyBindingRecord,
  capsuleHash,
  ephemeralKeyHash,
  rosterHash,
  verifyContribution,
  verifyEscrow,
  verifyReshareCommitments,
  verifyReshareKeyBinding,
  verifyRosterSignature,
  wrappedSharesHash,
} from '@encryption/src/crypto/council';
import { ensureSodium } from '@encryption/src/crypto/encryption';
import { base64ToUint8, importPublicKeyFromBytes, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { checkHelperCommitments, decodeCommitments, encodeCommitments, equalPoints, sumCommitments } from '@encryption/src/crypto/shamir';
import { verifyAuthPublicKeyBinding } from '@encryption/src/crypto/vault-unlock';
import type { CouncilRequest, Prisma } from '@encryption/src/generated/prisma/client';
import { prisma } from '@encryption/src/prisma/client';
import { requireStepUp } from '@encryption/src/server/auth/step-up';
import {
  type EscrowHealth,
  type RosterVersionRow,
  type SignedShareEntry,
  activateIfReady,
  activeIdentityIdsOf,
  councilChain,
  councilHead,
  councilProposal,
  escrowHealth,
  escrowRecordWire,
  proposalProgress,
  rosterRecordOf,
  rosterVersionWire,
  syncCouncilProposal,
} from '@encryption/src/server/council-core';
import {
  sendCouncilRecoveryAborted,
  sendCouncilRecoveryMeeting,
  sendCouncilRecoveryRequested,
  sendCouncilRecoveryToApprove,
  sendCouncilRosterToSign,
} from '@encryption/src/server/email/council';
import { env } from '@encryption/src/server/env';
import { errorResponses } from '@encryption/src/server/error-response';
import {
  COUNCIL_DEFAULT_REQUEST_TTL_DAYS,
  type RecoveryCouncilConfig,
  configuredCouncil,
  councilForEmail,
} from '@encryption/src/server/recovery-councils';
import { emergencyRecipient } from '@encryption/src/server/routes/emergency-core';
import { kdfParamsAllowed } from '@encryption/src/server/routes/kdf-params';
import { isRetryableRegistrationError } from '@encryption/src/server/routes/registration-core';
import { SKIP_SIG, activeIdentityWireKey, assertUserId, registerTransportAuth } from '@encryption/src/server/routes/transport-auth';
import { userFullName } from '@encryption/src/server/user-name';
import { configureZodValidation } from '@encryption/src/server/zod-validation';
import {
  API_ERROR_CONCURRENT_REGISTRATION,
  API_ERROR_COUNCIL_ALREADY_CONTRIBUTED,
  API_ERROR_COUNCIL_ESCROW_INVALID,
  API_ERROR_COUNCIL_ESCROW_UNRECOVERABLE,
  API_ERROR_COUNCIL_MEETING_REQUIRED,
  API_ERROR_COUNCIL_NOT_CUSTODIAN,
  API_ERROR_COUNCIL_NOT_FOUND,
  API_ERROR_COUNCIL_NO_ESCROW,
  API_ERROR_COUNCIL_REQUEST_CLOSED,
  API_ERROR_COUNCIL_REQUEST_EXISTS,
  API_ERROR_COUNCIL_REQUEST_NOT_FOUND,
  API_ERROR_COUNCIL_RESHARE_INVALID,
  API_ERROR_COUNCIL_ROSTER_CHANGED,
  API_ERROR_COUNCIL_SIGNATURE_INVALID,
  API_ERROR_RATE_LIMIT_COUNCIL,
  API_ERROR_VAULT_KDF_PARAMS_INVALID,
  API_ERROR_VAULT_NOT_FOUND,
} from '@encryption/src/shared/error-codes';
import {
  type CouncilCapsuleWire,
  CouncilCapsuleWireSchema,
  CouncilContributionBodySchema,
  type CouncilEscrowBody,
  CouncilEscrowBodySchema,
  CouncilEscrowRecordWireSchema,
  CouncilReleasedSharesSchema,
  CouncilReshareBatchSchema,
  CouncilReshareKeysBodySchema,
  CouncilReshareSubSharesBodySchema,
  RosterVersionWireSchema,
} from '@encryption/src/shared/schemas/recovery-council';

const DAY_MS = 24 * 60 * 60 * 1000;
const RESHARE_BATCH_SIZE = 100;
// A recovery request emails the user and every custodian: a stolen login asking,
// refusing and asking again must not turn that into a mail cannon. In memory, like
// the trusted contacts' limits (per instance, reset on restart).
const REQUEST_RATE_LIMIT_WINDOW_MS = DAY_MS;
const REQUEST_RATE_LIMIT_MAX = 3;

// How a request looks from the outside. Between `open` and `released`, the
// progress is derived from the contributions; the locked-out user only ever sees
// "in progress" or "go and see one of these people", never a count.
const RequestStageSchema = z.enum(['collecting', 'awaiting_meeting', 'cooldown', 'released', 'completed', 'aborted', 'expired']);
type RequestStage = z.infer<typeof RequestStageSchema>;

const EscrowHealthSchema = z.object({
  live: z.number().int().nonnegative(),
  threshold: z.number().int().positive(),
  status: z.enum(['ok', 'at-risk', 'lost']),
  outdated: z.boolean(),
});

function healthWire(health: EscrowHealth) {
  return { live: health.live, threshold: health.threshold, status: health.status, outdated: health.outdated };
}

function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

function councils(): RecoveryCouncilConfig[] {
  return env.RECOVERY_COUNCILS ?? [];
}

export function councilLabel(councilId: string): string {
  return configuredCouncil(councils(), councilId)?.label ?? councilId;
}

type EscrowWithParts = Prisma.CouncilEscrowGetPayload<{
  include: { capsules: true; credential: { include: { vault: true } }; signedRosterVersion: true };
}>;

/** The escrow a recovery request of this user is about: the one on their current vault, else their latest. */
async function escrowForRecovery(userId: string): Promise<EscrowWithParts | null> {
  const escrows = await prisma.councilEscrow.findMany({
    where: { userId },
    include: { capsules: true, credential: { include: { vault: true } }, signedRosterVersion: true },
    orderBy: { createdAt: 'desc' },
  });

  return escrows.find((e) => e.credential.vault.disabledAt === null) ?? escrows[0] ?? null;
}

async function healthOf(escrow: EscrowWithParts | Prisma.CouncilEscrowGetPayload<{ include: { capsules: true } }>): Promise<EscrowHealth> {
  const head = await councilHead(escrow.councilId);
  const active = await activeIdentityIdsOf(escrow.capsules.map((c) => c.identityId));

  return escrowHealth(escrow, head, active);
}

/** Slots whose current share can still be handed over: in the head with the same, still active key. */
async function liveSlots(escrow: {
  councilId: string;
  generation: number;
  capsules: Array<{ slot: number; identityId: string; generation: number }>;
}) {
  const head = await councilHead(escrow.councilId);
  const active = await activeIdentityIdsOf(escrow.capsules.map((c) => c.identityId));

  return escrow.capsules
    .filter(
      (c) =>
        c.generation === escrow.generation &&
        active.has(c.identityId) &&
        (head?.members.some((m) => m.slot === c.slot && m.identityId === c.identityId) ?? false)
    )
    .map((c) => ({ slot: c.slot, member: head!.members.find((m) => m.slot === c.slot)! }));
}

interface RequestFacts {
  request: CouncilRequest;
  threshold: number;
  contributions: Array<{ slot: number; inPerson: boolean }>;
  cooldownMinutes: number;
}

function requestStage({ request, threshold, contributions, cooldownMinutes }: RequestFacts, nowMs: number): RequestStage {
  if (request.status === 'completed') return 'completed';
  if (request.status === 'aborted') return 'aborted';
  if (request.expiresAt.getTime() <= nowMs) return 'expired';
  if (request.status === 'released') return 'released';

  const inPerson = contributions.filter((c) => c.inPerson).length;
  const remote = contributions.length - inPerson;

  if (contributions.length >= threshold && inPerson >= 1) {
    return request.createdAt.getTime() + cooldownMinutes * 60_000 <= nowMs ? 'released' : 'cooldown';
  }

  return remote >= threshold - 1 && inPerson === 0 ? 'awaiting_meeting' : 'collecting';
}

/**
 * Bring a request's stored status in line with its facts: the release (once the
 * shares are in and the cooldown elapsed) and the expiry are both lazy, like the
 * wait arithmetic of trusted contacts, so no job has to run for them to hold.
 */
async function settleRequest(requestId: string, nowMs: number): Promise<{ facts: RequestFacts; stage: RequestStage } | null> {
  const request = await prisma.councilRequest.findUnique({ where: { id: requestId }, include: { contributions: true, escrow: true } });
  if (!request) return null;

  const facts: RequestFacts = {
    request,
    threshold: request.escrow.threshold,
    contributions: request.contributions.map((c) => ({ slot: c.slot, inPerson: c.inPerson })),
    cooldownMinutes: configuredCouncil(councils(), request.escrow.councilId)?.cooldownMinutes ?? 0,
  };
  const stage = requestStage(facts, nowMs);

  if (stage === 'expired' && (request.status === 'open' || request.status === 'released')) {
    await prisma.$transaction([
      prisma.councilContribution.deleteMany({ where: { requestId } }),
      prisma.councilRequest.update({ where: { id: requestId }, data: { status: 'aborted', closedAt: new Date(nowMs) } }),
    ]);
  } else if (stage === 'released' && request.status === 'open') {
    await prisma.councilRequest.updateMany({ where: { id: requestId, status: 'open' }, data: { status: 'released', releasedAt: new Date(nowMs) } });
    facts.request = { ...request, status: 'released', releasedAt: new Date(nowMs) };
  }

  return { facts, stage };
}

async function openRequestOf(userId: string): Promise<CouncilRequest | null> {
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

function sendSignatureError(reply: FastifyReply) {
  return reply.status(400).send({ code: API_ERROR_COUNCIL_SIGNATURE_INVALID });
}

type SyncResults = Map<string, Awaited<ReturnType<typeof syncCouncilProposal>>>;

/**
 * Bring every configured council's proposal in line with the configuration, and
 * email the people a NEW proposal waits on (its members and the custodians of
 * the head). Run at boot and on the council reads, so a change of the variable
 * reaches the custodians without anyone having to look first. A council whose
 * sync fails (two instances racing to write the same proposal) is skipped: the
 * next run catches up.
 */
export async function syncConfiguredCouncils(log: FastifyBaseLogger): Promise<SyncResults> {
  const results: SyncResults = new Map();
  const productUrl = env.EMAIL_PRODUCT_URL ?? '';

  for (const config of councils()) {
    try {
      const before = await councilProposal(config.id);
      const result = await syncCouncilProposal(config);
      results.set(config.id, result);

      if (result.proposal && result.proposal.id !== before?.id) {
        const head = await councilHead(config.id);
        const notify = new Set([...result.proposal.members.map((m) => m.userId), ...(head?.members.map((m) => m.userId) ?? [])]);

        for (const userId of notify) {
          const recipient = await emergencyRecipient(userId);
          if (recipient)
            sendCouncilRosterToSign({ recipient: recipient.email, locale: recipient.locale, council: config.label, productUrl }).catch(
              (err: unknown) => log.error({ err }, 'recovery council email failed: roster to sign')
            );
        }
      }
    } catch (err) {
      log.warn({ err, councilId: config.id }, 'recovery council sync skipped');
    }
  }

  return results;
}

export async function recoveryCouncilRoute(app: FastifyInstance): Promise<void> {
  configureZodValidation(app);
  registerTransportAuth(app);

  const requestHits = new Map<string, number[]>();
  const requestAllowed = (userId: string, nowMs: number): boolean => {
    const kept = (requestHits.get(userId) ?? []).filter((t) => t > nowMs - REQUEST_RATE_LIMIT_WINDOW_MS);
    if (kept.length >= REQUEST_RATE_LIMIT_MAX) return false;

    requestHits.set(userId, [...kept, nowMs]);

    return true;
  };

  const productUrl = env.EMAIL_PRODUCT_URL ?? '';

  function logEmailFailure(context: string) {
    return (err: unknown) => app.log.error({ err }, `recovery council email failed: ${context}`);
  }

  const syncAll = () => syncConfiguredCouncils(app.log);

  // Which councils the caller sits in, as a custodian of the head or as someone a
  // proposal adds. Anyone else gets an empty list and no detail at all: the
  // interface only learns "you are a custodian of these councils".
  app.withTypeProvider<ZodTypeProvider>().get(
    '/api/councils/mine',
    {
      ...SKIP_SIG,
      schema: {
        response: {
          200: z.object({
            mfa_enforced: z.boolean(),
            councils: z.array(
              z.object({
                council_id: z.string(),
                label: z.string(),
                role: z.enum(['custodian', 'invited']),
                configured: z.boolean(),
                my_slot: z.number().int().nullable(),
                chain: z.array(RosterVersionWireSchema),
                proposal: z
                  .object({
                    roster: RosterVersionWireSchema,
                    quorum_missing: z.number().int().nonnegative(),
                    pending_members: z.array(z.object({ slot: z.number().int(), name: z.string() })),
                    signed_by_me: z.boolean(),
                    may_sign: z.boolean(),
                  })
                  .nullable(),
                blocked: z.array(z.object({ email: z.string(), reason: z.enum(['unknown-user', 'email-mismatch', 'not-onboarded']) })),
                health: z.object({
                  escrows: z.number().int().nonnegative(),
                  ok: z.number().int().nonnegative(),
                  at_risk: z.number().int().nonnegative(),
                  lost: z.number().int().nonnegative(),
                  outdated: z.array(z.object({ version: z.number().int(), escrows: z.number().int() })),
                }),
                requests: z.array(
                  z.object({
                    id: z.string().uuid(),
                    user_name: z.string().nullable(),
                    user_email: z.string(),
                    created_at_millis: z.number().int(),
                    expires_at_millis: z.number().int(),
                    stage: RequestStageSchema,
                    contributors: z.array(z.object({ slot: z.number().int(), name: z.string(), in_person: z.boolean() })),
                    my_contribution: z.enum(['none', 'remote', 'in_person']),
                    can_contribute: z.boolean(),
                  })
                ),
                reshare: z
                  .object({
                    session_id: z.string().uuid(),
                    source_version: z.number().int(),
                    target_version: z.number().int(),
                    helper_slots: z.array(z.number().int()),
                    i_am_helper: z.boolean(),
                    remaining_for_me: z.number().int().nonnegative(),
                    remaining: z.number().int().nonnegative(),
                  })
                  .nullable(),
              })
            ),
          }),
        },
      },
    },
    async (request) => {
      assertUserId(request);
      const userId = request.userId;
      const synced = await syncAll();
      const now = Date.now();

      const memberships = await prisma.councilRosterMember.findMany({
        where: { userId, rosterVersion: { status: { in: ['active', 'proposed'] } } },
        include: { rosterVersion: true },
      });
      const councilIds = [...new Set(memberships.map((m) => m.rosterVersion.councilId))];

      const result = [];

      for (const councilId of councilIds) {
        const [head, proposal, chain] = await Promise.all([councilHead(councilId), councilProposal(councilId), councilChain(councilId)]);
        const myHeadMember = head?.members.find((m) => m.userId === userId) ?? null;
        const role = myHeadMember ? ('custodian' as const) : ('invited' as const);
        const config = configuredCouncil(councils(), councilId);
        const myIdentity = await prisma.identity.findFirst({ where: { userId, disabledAt: null }, orderBy: { generation: 'desc' } });

        let proposalWire = null;
        if (proposal) {
          const progress = proposalProgress(proposal, head);
          const inProposal = proposal.members.some((m) => m.userId === userId && m.identityId === myIdentity?.id);
          const inHead = myHeadMember !== null && myHeadMember.identityId === myIdentity?.id;

          proposalWire = {
            roster: rosterVersionWire(proposal),
            quorum_missing: progress.quorumMissing,
            pending_members: progress.pendingMembers.map((p) => {
              const member = proposal.members.find((m) => m.slot === p.slot)!;
              return { slot: p.slot, name: userFullName(member.user) ?? member.user.email };
            }),
            signed_by_me: proposal.signatures.some((s) => s.identityId === myIdentity?.id),
            may_sign: inProposal || inHead,
          };
        }

        // Health and requests are a custodian's business, not an invitee's.
        const health = { escrows: 0, ok: 0, at_risk: 0, lost: 0, outdated: [] as Array<{ version: number; escrows: number }> };
        const requests = [];
        let reshare = null;

        if (role === 'custodian' && head) {
          const escrows = await prisma.councilEscrow.findMany({ where: { councilId }, include: { capsules: true, rosterVersion: true } });
          const active = await activeIdentityIdsOf([...new Set(escrows.flatMap((e) => e.capsules.map((c) => c.identityId)))]);
          const outdated = new Map<number, number>();

          for (const escrow of escrows) {
            const h = escrowHealth(escrow, head, active);
            health.escrows++;
            if (h.status === 'ok') health.ok++;
            else if (h.status === 'at-risk') health.at_risk++;
            else health.lost++;
            if (h.outdated) outdated.set(escrow.rosterVersion.version, (outdated.get(escrow.rosterVersion.version) ?? 0) + 1);
          }
          health.outdated = [...outdated.entries()].sort(([a], [b]) => a - b).map(([version, count]) => ({ version, escrows: count }));

          const open = await prisma.councilRequest.findMany({
            where: { escrow: { councilId }, status: { in: ['open', 'released'] } },
            include: { user: true, escrow: { include: { capsules: true } }, contributions: true },
            orderBy: { createdAt: 'asc' },
          });

          for (const row of open) {
            const settled = await settleRequest(row.id, now);
            if (!settled || settled.stage === 'expired') continue;

            const mine = row.contributions.find((c) => c.slot === myHeadMember!.slot);
            const myCapsule = row.escrow.capsules.find(
              (c) => c.slot === myHeadMember!.slot && c.generation === row.escrow.generation && c.identityId === myHeadMember!.identityId
            );
            const contributors = row.contributions.map((c) => {
              const member = head.members.find((m) => m.slot === c.slot);
              return { slot: c.slot, name: member ? (userFullName(member.user) ?? member.user.email) : `#${c.slot}`, in_person: c.inPerson };
            });

            requests.push({
              id: row.id,
              user_name: userFullName(row.user),
              user_email: row.user.email,
              created_at_millis: row.createdAt.getTime(),
              expires_at_millis: row.expiresAt.getTime(),
              stage: settled.stage,
              contributors,
              my_contribution: mine ? (mine.inPerson ? ('in_person' as const) : ('remote' as const)) : ('none' as const),
              can_contribute: !mine && myCapsule !== undefined && (settled.stage === 'collecting' || settled.stage === 'awaiting_meeting'),
            });
          }

          const session = await prisma.councilReshareSession.findFirst({
            where: { councilId, status: 'open' },
            include: { sourceRosterVersion: true, targetRosterVersion: true },
          });
          if (session) {
            const progress = await reshareProgress(session.id, myHeadMember!.slot);
            reshare = {
              session_id: session.id,
              source_version: session.sourceRosterVersion.version,
              target_version: session.targetRosterVersion.version,
              helper_slots: session.helperSlots,
              i_am_helper: session.helperSlots.includes(myHeadMember!.slot),
              remaining_for_me: progress.remainingForMe,
              remaining: progress.remaining,
            };
          }
        }

        result.push({
          council_id: councilId,
          label: config?.label ?? councilId,
          role,
          configured: config !== null,
          my_slot: myHeadMember?.slot ?? null,
          chain: chain.map(rosterVersionWire),
          proposal: proposalWire,
          blocked: (synced.get(councilId)?.blocked ?? []).map((b) => ({ email: b.email, reason: b.reason })),
          health,
          requests,
          reshare,
        });
      }

      return { mfa_enforced: env.OIDC_STEP_UP_ENABLED, councils: result };
    }
  );

  // The council that covers the caller, with the signed chain their vault
  // verifies, and the state of their own escrow. Names are shown: users accept a
  // council knowing who is in it, and will have to go and see them.
  app.withTypeProvider<ZodTypeProvider>().get(
    '/api/councils/for-me',
    {
      ...SKIP_SIG,
      schema: {
        response: {
          200: z.object({
            council: z
              .object({
                council_id: z.string(),
                label: z.string(),
                configured: z.boolean(),
                chain: z.array(RosterVersionWireSchema),
              })
              .nullable(),
            escrow: z
              .object({
                id: z.string().uuid(),
                council_id: z.string(),
                vault_active: z.boolean(),
                generation: z.number().int().positive(),
                current_version: z.number().int().positive(),
                record: CouncilEscrowRecordWireSchema,
                health: EscrowHealthSchema,
              })
              .nullable(),
          }),
        },
      },
    },
    async (request) => {
      assertUserId(request);
      const userId = request.userId;
      await syncAll();

      const user = await prisma.user.findUnique({ where: { id: userId } });
      const escrow = await escrowForRecovery(userId);
      const councilId = escrow?.councilId ?? (user ? councilForEmail(councils(), user.email)?.id : undefined);

      let council = null;
      if (councilId) {
        const chain = await councilChain(councilId);
        council =
          chain.length > 0
            ? {
                council_id: councilId,
                label: councilLabel(councilId),
                configured: configuredCouncil(councils(), councilId) !== null,
                chain: chain.map(rosterVersionWire),
              }
            : null;
      }

      let escrowWire = null;
      if (escrow) {
        const current = await prisma.councilRosterVersion.findUniqueOrThrow({ where: { id: escrow.rosterVersionId } });
        escrowWire = {
          id: escrow.id,
          council_id: escrow.councilId,
          vault_active: escrow.credential.vault.disabledAt === null,
          generation: escrow.generation,
          current_version: current.version,
          record: escrowRecordWire(escrow, sha256(new Uint8Array(escrow.credential.authPublicKey))),
          health: healthWire(await healthOf(escrow)),
        };
      }

      return { council, escrow: escrowWire };
    }
  );

  // A custodian (or someone a proposal adds) signs a roster version. Their vault
  // signed the exact payload rebuilt from what they were shown; the server checks
  // it against the same payload rebuilt from the database, so a version that
  // changed in between is refused rather than signed blind.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/councils/:councilId/versions/:version/sign',
    {
      schema: {
        params: z.object({ councilId: z.string().min(1).max(64), version: z.coerce.number().int().positive() }),
        body: z.object({ signature: z.string().min(1).max(1024) }),
        response: { 200: z.object({ activated: z.boolean() }), ...errorResponses(400, 401, 403, 404, 409) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      if (!requireStepUp(request, reply)) return reply;

      const userId = request.userId;
      const proposal = await councilProposal(request.params.councilId);
      if (!proposal) return reply.status(404).send({ code: API_ERROR_COUNCIL_NOT_FOUND });
      if (proposal.version !== request.params.version) return reply.status(409).send({ code: API_ERROR_COUNCIL_ROSTER_CHANGED });

      const identity = await prisma.identity.findFirst({ where: { userId, disabledAt: null }, orderBy: { generation: 'desc' } });
      if (!identity) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

      const head = await councilHead(request.params.councilId);
      const mayVouch = proposal.members.some((m) => m.userId === userId && m.identityId === identity.id);
      const mayApprove = head?.members.some((m) => m.userId === userId && m.identityId === identity.id) ?? false;
      if (!mayVouch && !mayApprove) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const signature = base64ToUint8(request.body.signature);
      if (!(await verifyRosterSignature(rosterRecordOf(proposal), signature, new Uint8Array(identity.signaturePublicKey))))
        return sendSignatureError(reply);

      await prisma.councilRosterSignature.upsert({
        where: { rosterVersionId_identityId: { rosterVersionId: proposal.id, identityId: identity.id } },
        create: { rosterVersionId: proposal.id, identityId: identity.id, signature: Buffer.from(signature) },
        update: { signature: Buffer.from(signature) },
      });

      const activated = await activateIfReady(request.params.councilId);

      return { activated: activated !== null };
    }
  );

  // Enroll (or re-enroll) the caller's current vault with the head of their
  // council. Explicit and identity-signed: the vault built it after the user
  // accepted the council in the interface. A previous escrow of this vault is
  // replaced; one with a recovery in progress is not.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/councils/escrow',
    {
      schema: {
        body: CouncilEscrowBodySchema,
        response: { 200: z.object({ id: z.string().uuid() }), ...errorResponses(400, 404, 409) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const userId = request.userId;
      const body = request.body;

      const keyring = await prisma.vaultKeyring.findFirst({ where: { userId, disabledAt: null } });
      if (!keyring) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

      const pending = await openRequestOf(userId);
      if (pending) return reply.status(409).send({ code: API_ERROR_COUNCIL_REQUEST_EXISTS });

      const checked = await checkEscrowSubmission(userId, body);
      if (!checked.ok) return reply.status(checked.status).send({ code: checked.code });

      try {
        const created = await prisma.$transaction(
          async (tx) => {
            const previous = await tx.councilEscrow.findMany({
              where: { userId, credential: { vaultId: keyring.id } },
              select: { credentialId: true },
            });
            const id = await writeEscrow(tx, userId, keyring.id, body, checked);
            await tx.vaultCredential.deleteMany({ where: { id: { in: previous.map((p) => p.credentialId) } } });

            return id;
          },
          { isolationLevel: 'Serializable' }
        );

        return { id: created };
      } catch (err) {
        if (isRetryableRegistrationError(err)) return reply.status(409).send({ code: API_ERROR_CONCURRENT_REGISTRATION });
        throw err;
      }
    }
  );

  // ----- Recovery requests (the locked-out user) -------------------------------

  // Ask the council. ID token only: the user has no vault left to sign with, and
  // nothing reached this way opens anything without someone meeting them. The
  // email to the user is load-bearing (a stolen login must not ask silently), so
  // a failed send fails the call.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/council-recovery/requests',
    {
      ...SKIP_SIG,
      schema: {
        body: z.object({ ephemeral_public_key: z.string().min(1).max(4096) }),
        response: { 200: z.object({ id: z.string().uuid(), expires_at_millis: z.number().int() }), ...errorResponses(400, 404, 409, 429) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const userId = request.userId;

      const escrow = await escrowForRecovery(userId);
      if (!escrow) return reply.status(404).send({ code: API_ERROR_COUNCIL_NO_ESCROW });
      if ((await healthOf(escrow)).status === 'lost') return reply.status(409).send({ code: API_ERROR_COUNCIL_ESCROW_UNRECOVERABLE });
      if (await openRequestOf(userId)) return reply.status(409).send({ code: API_ERROR_COUNCIL_REQUEST_EXISTS });
      if (!requestAllowed(userId, Date.now())) return reply.status(429).send({ code: API_ERROR_RATE_LIMIT_COUNCIL });

      const user = await emergencyRecipient(userId);
      if (!user) return reply.status(404).send({ code: API_ERROR_COUNCIL_NO_ESCROW });

      const label = councilLabel(escrow.councilId);
      await sendCouncilRecoveryRequested({ recipient: user.email, locale: user.locale, council: label, productUrl });

      const ttlDays = configuredCouncil(councils(), escrow.councilId)?.requestTtlDays ?? COUNCIL_DEFAULT_REQUEST_TTL_DAYS;
      const created = await prisma.councilRequest.create({
        data: {
          userId,
          escrowId: escrow.id,
          ephemeralPublicKey: Buffer.from(base64ToUint8(request.body.ephemeral_public_key)),
          status: 'open',
          expiresAt: new Date(Date.now() + ttlDays * DAY_MS),
        },
      });

      for (const { member } of await liveSlots(escrow)) {
        const custodian = await emergencyRecipient(member.userId);
        if (custodian)
          sendCouncilRecoveryToApprove({
            recipient: custodian.email,
            locale: custodian.locale,
            requester: user.labelWithEmail,
            council: label,
            productUrl,
          }).catch(logEmailFailure('to approve'));
      }

      return { id: created.id, expires_at_millis: created.expiresAt.getTime() };
    }
  );

  // The user's own view: "in progress", then "go and see one of these people".
  // No count and no names before that point.
  app.withTypeProvider<ZodTypeProvider>().get(
    '/api/council-recovery/requests/mine',
    {
      ...SKIP_SIG,
      schema: {
        response: {
          200: z.object({
            request: z
              .object({
                id: z.string().uuid(),
                council_label: z.string(),
                stage: z.enum(['in_progress', 'meet', 'released']),
                created_at_millis: z.number().int(),
                expires_at_millis: z.number().int(),
                meet: z.array(z.object({ name: z.string() })),
              })
              .nullable(),
          }),
        },
      },
    },
    async (request) => {
      assertUserId(request);
      const open = await openRequestOf(request.userId);
      if (!open) return { request: null };

      const settled = (await settleRequest(open.id, Date.now()))!;
      const escrow = await prisma.councilEscrow.findUniqueOrThrow({ where: { id: open.escrowId }, include: { capsules: true } });
      const stage = settled.stage === 'released' ? 'released' : settled.stage === 'awaiting_meeting' ? 'meet' : 'in_progress';

      const contributed = new Set(settled.facts.contributions.map((c) => c.slot));
      const meet =
        stage === 'meet'
          ? (await liveSlots(escrow))
              .filter((s) => !contributed.has(s.slot))
              .map((s) => ({ name: userFullName(s.member.user) ?? s.member.user.email }))
          : [];

      return {
        request: {
          id: open.id,
          council_label: councilLabel(escrow.councilId),
          stage: stage as 'in_progress' | 'meet' | 'released',
          created_at_millis: open.createdAt.getTime(),
          expires_at_millis: open.expiresAt.getTime(),
          meet,
        },
      };
    }
  );

  // The user stops their own request (or one a stolen login opened). Fail-safe,
  // so a bare login is enough; the shares already handed over are discarded.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/council-recovery/requests/:id/refuse',
    {
      ...SKIP_SIG,
      schema: { params: z.object({ id: z.string().uuid() }), response: { 200: z.object({ refused: z.boolean() }), ...errorResponses(404) } },
    },
    async (request, reply) => {
      assertUserId(request);
      const row = await prisma.councilRequest.findUnique({ where: { id: request.params.id } });
      if (!row || row.userId !== request.userId) return reply.status(404).send({ code: API_ERROR_COUNCIL_REQUEST_NOT_FOUND });

      await prisma.$transaction([
        prisma.councilContribution.deleteMany({ where: { requestId: row.id } }),
        prisma.councilRequest.updateMany({
          where: { id: row.id, status: { in: ['open', 'released'] } },
          data: { status: 'aborted', closedAt: new Date() },
        }),
      ]);

      return { refused: true };
    }
  );

  // Released: the shares, wrapped for the ephemeral key of the browser that asked,
  // with the signed escrow record the vault checks them against.
  app.withTypeProvider<ZodTypeProvider>().get(
    '/api/council-recovery/requests/:id/shares',
    {
      ...SKIP_SIG,
      schema: { params: z.object({ id: z.string().uuid() }), response: { 200: CouncilReleasedSharesSchema, ...errorResponses(400, 404) } },
    },
    async (request, reply) => {
      assertUserId(request);
      const row = await prisma.councilRequest.findUnique({ where: { id: request.params.id } });
      if (!row || row.userId !== request.userId) return reply.status(404).send({ code: API_ERROR_COUNCIL_REQUEST_NOT_FOUND });

      const settled = await settleRequest(row.id, Date.now());
      if (settled?.stage !== 'released') return reply.status(400).send({ code: API_ERROR_COUNCIL_REQUEST_CLOSED });

      const escrow = await prisma.councilEscrow.findUniqueOrThrow({
        where: { id: row.escrowId },
        include: { credential: true, signedRosterVersion: true },
      });
      const contributions = await prisma.councilContribution.findMany({
        where: { requestId: row.id },
        include: { custodianIdentity: { include: { user: true } } },
        orderBy: { slot: 'asc' },
      });

      return {
        request_id: row.id,
        council_id: escrow.councilId,
        user_id: row.userId,
        generation: escrow.generation,
        threshold: escrow.threshold,
        share_commitments: uint8ToBase64(new Uint8Array(escrow.commitments)),
        lang: escrow.credential.lang,
        escrow: escrowRecordWire(escrow, sha256(new Uint8Array(escrow.credential.authPublicKey))),
        contributions: contributions.map((c) => ({
          slot: c.slot,
          wrapped_share: c.wrappedShare,
          in_person: c.inPerson,
          signature: uint8ToBase64(new Uint8Array(c.signature)),
          custodian_user_id: c.custodianIdentity.userId,
          custodian_identity_public_key: uint8ToBase64(new Uint8Array(c.custodianIdentity.signaturePublicKey)),
          custodian_name: userFullName(c.custodianIdentity.user),
        })),
      };
    }
  );

  // ----- Recovery requests (custodians) ----------------------------------------

  async function custodianOf(councilId: string, userId: string) {
    const head = await councilHead(councilId);
    const identity = await prisma.identity.findFirst({ where: { userId, disabledAt: null }, orderBy: { generation: 'desc' } });
    const member = head?.members.find((m) => m.userId === userId && m.identityId === identity?.id) ?? null;

    return member && identity ? { head: head!, member, identity } : null;
  }

  // What a custodian's vault needs to hand over their share: the request's
  // ephemeral key, the user's signed escrow record, and their own capsule.
  app.withTypeProvider<ZodTypeProvider>().get(
    '/api/council-recovery/requests/:id/custodian',
    {
      ...SKIP_SIG,
      schema: {
        params: z.object({ id: z.string().uuid() }),
        response: {
          200: z.object({
            id: z.string().uuid(),
            council_id: z.string(),
            user_id: z.string().uuid(),
            user_name: z.string().nullable(),
            user_email: z.string(),
            ephemeral_public_key: z.string(),
            stage: RequestStageSchema,
            meeting_required: z.boolean(),
            escrow: CouncilEscrowRecordWireSchema,
            capsule: CouncilCapsuleWireSchema,
          }),
          ...errorResponses(400, 403, 404),
        },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const row = await prisma.councilRequest.findUnique({
        where: { id: request.params.id },
        include: { user: true, escrow: { include: { capsules: true, credential: true, signedRosterVersion: true } } },
      });
      if (!row) return reply.status(404).send({ code: API_ERROR_COUNCIL_REQUEST_NOT_FOUND });

      const custodian = await custodianOf(row.escrow.councilId, request.userId);
      if (!custodian) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const settled = (await settleRequest(row.id, Date.now()))!;
      if (settled.stage !== 'collecting' && settled.stage !== 'awaiting_meeting')
        return reply.status(400).send({ code: API_ERROR_COUNCIL_REQUEST_CLOSED });

      const capsule = row.escrow.capsules.find(
        (c) => c.slot === custodian.member.slot && c.generation === row.escrow.generation && c.identityId === custodian.identity.id
      );
      if (!capsule) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const inPerson = settled.facts.contributions.filter((c) => c.inPerson).length;
      const remote = settled.facts.contributions.length - inPerson;

      return {
        id: row.id,
        council_id: row.escrow.councilId,
        user_id: row.userId,
        user_name: userFullName(row.user),
        user_email: row.user.email,
        ephemeral_public_key: uint8ToBase64(new Uint8Array(row.ephemeralPublicKey)),
        stage: settled.stage,
        meeting_required: remote >= row.escrow.threshold - 1,
        escrow: escrowRecordWire(row.escrow, sha256(new Uint8Array(row.escrow.credential.authPublicKey))),
        capsule: await capsuleWire(capsule, row.escrowId),
      };
    }
  );

  // Hand over one share. Identity-signed with a fresh authentication. Remote
  // contributions stop at threshold - 1: the last share is always one a custodian
  // handed over after checking the code on the person's own screen.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/council-recovery/requests/:id/contribute',
    {
      schema: {
        params: z.object({ id: z.string().uuid() }),
        body: CouncilContributionBodySchema,
        response: { 200: z.object({ stage: RequestStageSchema }), ...errorResponses(400, 401, 403, 404, 409) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      if (!requireStepUp(request, reply)) return reply;

      const body = request.body;
      const row = await prisma.councilRequest.findUnique({ where: { id: request.params.id }, include: { escrow: { include: { capsules: true } } } });
      if (!row) return reply.status(404).send({ code: API_ERROR_COUNCIL_REQUEST_NOT_FOUND });

      const custodian = await custodianOf(row.escrow.councilId, request.userId);
      if (!custodian || custodian.member.slot !== body.slot) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const hasCapsule = row.escrow.capsules.some(
        (c) => c.slot === body.slot && c.generation === row.escrow.generation && c.identityId === custodian.identity.id
      );
      if (!hasCapsule) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const now = Date.now();
      const settled = (await settleRequest(row.id, now))!;
      if (settled.stage !== 'collecting' && settled.stage !== 'awaiting_meeting')
        return reply.status(400).send({ code: API_ERROR_COUNCIL_REQUEST_CLOSED });
      if (settled.facts.contributions.some((c) => c.slot === body.slot))
        return reply.status(409).send({ code: API_ERROR_COUNCIL_ALREADY_CONTRIBUTED });

      const remote = settled.facts.contributions.filter((c) => !c.inPerson).length;
      if (!body.in_person && remote >= row.escrow.threshold - 1) return reply.status(409).send({ code: API_ERROR_COUNCIL_MEETING_REQUIRED });

      const record: ContributionRecord = {
        requestId: row.id,
        userId: row.userId,
        councilId: row.escrow.councilId,
        slot: body.slot,
        custodianUserId: request.userId,
        ephemeralPublicKeyHash: await ephemeralKeyHash(new Uint8Array(row.ephemeralPublicKey)),
        wrappedSharesHash: await wrappedSharesHash([base64ToUint8(body.wrapped_share)]),
        inPerson: body.in_person,
      };
      const signature = base64ToUint8(body.signature);
      if (!(await verifyContribution(record, signature, new Uint8Array(custodian.identity.signaturePublicKey)))) return sendSignatureError(reply);

      try {
        await prisma.councilContribution.create({
          data: {
            requestId: row.id,
            slot: body.slot,
            custodianIdentityId: custodian.identity.id,
            wrappedShare: body.wrapped_share,
            inPerson: body.in_person,
            signature: Buffer.from(signature),
          },
        });
      } catch (err) {
        if (isRetryableRegistrationError(err)) return reply.status(409).send({ code: API_ERROR_COUNCIL_ALREADY_CONTRIBUTED });
        throw err;
      }

      const after = (await settleRequest(row.id, now))!;

      // Reaching the meeting step is when the user learns who to go and see.
      if (after.stage === 'awaiting_meeting' && settled.stage !== 'awaiting_meeting') {
        const user = await emergencyRecipient(row.userId);
        const contributed = new Set(after.facts.contributions.map((c) => c.slot));
        const names = (await liveSlots(row.escrow))
          .filter((s) => !contributed.has(s.slot))
          .map((s) => userFullName(s.member.user) ?? s.member.user.email)
          .join(', ');
        if (user)
          sendCouncilRecoveryMeeting({
            recipient: user.email,
            locale: user.locale,
            council: councilLabel(row.escrow.councilId),
            custodians: names,
            productUrl,
          }).catch(logEmailFailure('meeting'));
      }

      return { stage: after.stage };
    }
  );

  // A custodian stops a request they find suspicious. Identity-signed with a
  // fresh authentication: denying a recovery is the most it can do.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/council-recovery/requests/:id/abort',
    {
      schema: {
        params: z.object({ id: z.string().uuid() }),
        response: { 200: z.object({ aborted: z.boolean() }), ...errorResponses(401, 403, 404) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      if (!requireStepUp(request, reply)) return reply;

      const row = await prisma.councilRequest.findUnique({ where: { id: request.params.id }, include: { escrow: true } });
      if (!row) return reply.status(404).send({ code: API_ERROR_COUNCIL_REQUEST_NOT_FOUND });
      if (!(await custodianOf(row.escrow.councilId, request.userId))) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const [, updated] = await prisma.$transaction([
        prisma.councilContribution.deleteMany({ where: { requestId: row.id } }),
        prisma.councilRequest.updateMany({
          where: { id: row.id, status: { in: ['open', 'released'] } },
          data: { status: 'aborted', closedAt: new Date() },
        }),
      ]);

      if (updated.count > 0) {
        const user = await emergencyRecipient(row.userId);
        if (user)
          sendCouncilRecoveryAborted({ recipient: user.email, locale: user.locale, council: councilLabel(row.escrow.councilId) }).catch(
            logEmailFailure('aborted')
          );
      }

      return { aborted: updated.count > 0 };
    }
  );

  // ----- Resharing --------------------------------------------------------------

  async function reshareProgress(sessionId: string, mySlot: number): Promise<{ remaining: number; remainingForMe: number }> {
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

  // Start moving the escrows split over an older version to the head. The helpers
  // are `threshold` custodians of that version still in the head with the same
  // key; each then processes the escrows from their own vault.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/councils/:councilId/reshare',
    {
      schema: {
        params: z.object({ councilId: z.string().min(1).max(64) }),
        body: z.object({ source_version: z.number().int().positive(), helper_slots: z.array(z.number().int().min(1).max(255)).min(1).max(12) }),
        response: { 200: z.object({ session_id: z.string().uuid() }), ...errorResponses(400, 401, 403, 404, 409) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      if (!requireStepUp(request, reply)) return reply;

      const { councilId } = request.params;
      const custodian = await custodianOf(councilId, request.userId);
      if (!custodian) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const source = await prisma.councilRosterVersion.findUnique({
        where: { councilId_version: { councilId, version: request.body.source_version } },
        include: { members: true },
      });
      if (!source || source.id === custodian.head.id || source.status === 'proposed')
        return reply.status(400).send({ code: API_ERROR_COUNCIL_RESHARE_INVALID });

      const helpers = [...new Set(request.body.helper_slots)];
      const helpersValid =
        helpers.length === source.threshold &&
        helpers.every((slot) => {
          const before = source.members.find((m) => m.slot === slot);
          return before && custodian.head.members.some((m) => m.slot === slot && m.identityId === before.identityId);
        });
      if (!helpersValid) return reply.status(400).send({ code: API_ERROR_COUNCIL_RESHARE_INVALID });

      if (await prisma.councilReshareSession.findFirst({ where: { councilId, status: 'open' } }))
        return reply.status(409).send({ code: API_ERROR_COUNCIL_RESHARE_INVALID });

      const session = await prisma.councilReshareSession.create({
        data: {
          councilId,
          sourceRosterVersionId: source.id,
          targetRosterVersionId: custodian.head.id,
          helperSlots: helpers,
          status: 'open',
          createdByUserId: request.userId,
        },
      });

      return { session_id: session.id };
    }
  );

  async function helperOf(sessionId: string, userId: string) {
    const session = await prisma.councilReshareSession.findUnique({ where: { id: sessionId } });
    if (!session || session.status !== 'open') return null;

    const custodian = await custodianOf(session.councilId, userId);
    if (!custodian || !session.helperSlots.includes(custodian.member.slot) || custodian.head.id !== session.targetRosterVersionId) return null;

    return { session, ...custodian };
  }

  // A helper's next batch: the escrows they have not processed yet, with their own
  // capsule of each, and the signed chain their vault verifies the target against.
  app.withTypeProvider<ZodTypeProvider>().get(
    '/api/councils/reshare/:sessionId/batch',
    {
      ...SKIP_SIG,
      schema: { params: z.object({ sessionId: z.string().uuid() }), response: { 200: CouncilReshareBatchSchema, ...errorResponses(403) } },
    },
    async (request, reply) => {
      assertUserId(request);
      const helper = await helperOf(request.params.sessionId, request.userId);
      if (!helper) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const { session, member } = helper;
      const done = new Set(
        (
          await prisma.councilSubShare.findMany({
            where: { sessionId: session.id, helperSlot: member.slot },
            distinct: ['escrowId'],
            select: { escrowId: true },
          })
        ).map((s) => s.escrowId)
      );
      const escrows = await prisma.councilEscrow.findMany({
        where: { councilId: session.councilId, rosterVersionId: session.sourceRosterVersionId },
        include: { capsules: true, credential: true, signedRosterVersion: true },
        orderBy: { createdAt: 'asc' },
      });
      const eligible = escrows.filter(
        (e) => !done.has(e.id) && session.helperSlots.every((slot) => e.capsules.some((c) => c.slot === slot && c.generation === e.generation))
      );

      const batch = [];
      for (const escrow of eligible.slice(0, RESHARE_BATCH_SIZE)) {
        const capsule = escrow.capsules.find((c) => c.slot === member.slot && c.generation === escrow.generation)!;
        batch.push({
          escrow_id: escrow.id,
          user_id: escrow.userId,
          record: escrowRecordWire(escrow, sha256(new Uint8Array(escrow.credential.authPublicKey))),
          capsule: await capsuleWire(capsule, escrow.id),
        });
      }

      const target = await prisma.councilRosterVersion.findUniqueOrThrow({ where: { id: session.targetRosterVersionId } });
      const keys = await prisma.councilReshareKey.count({ where: { sessionId: session.id, helperSlot: member.slot } });

      return {
        session_id: session.id,
        council_id: session.councilId,
        helper_slots: session.helperSlots,
        my_slot: member.slot,
        target_roster_version: target.version,
        target_threshold: target.threshold,
        chain: (await councilChain(session.councilId)).map(rosterVersionWire),
        transfer_keys_done: keys > 0,
        escrows: batch,
        remaining: eligible.length,
      };
    }
  );

  // A helper's transfer keys, one per custodian of the target, each signed so a
  // new custodian only ever adds up sub-shares from a real helper.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/councils/reshare/:sessionId/keys',
    {
      schema: {
        params: z.object({ sessionId: z.string().uuid() }),
        body: CouncilReshareKeysBodySchema,
        response: { 200: z.object({ stored: z.number().int() }), ...errorResponses(400, 403) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const helper = await helperOf(request.params.sessionId, request.userId);
      if (!helper) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const { session, member, head, identity } = helper;
      const targetSlots = head.members.map((m) => m.slot).sort((a, b) => a - b);
      const sent = request.body.keys.map((k) => k.recipient_slot).sort((a, b) => a - b);
      if (sent.length !== targetSlots.length || sent.some((slot, i) => slot !== targetSlots[i]))
        return reply.status(400).send({ code: API_ERROR_COUNCIL_RESHARE_INVALID });

      for (const key of request.body.keys) {
        const binding: ReshareKeyBindingRecord = {
          sessionId: session.id,
          councilId: session.councilId,
          targetRosterVersion: head.version,
          helperSlot: member.slot,
          recipientSlot: key.recipient_slot,
          wrappedTransferKeyHash: sha256(base64ToUint8(key.wrapped_transfer_key)),
        };
        if (!(await verifyReshareKeyBinding(binding, base64ToUint8(key.binding_signature), new Uint8Array(identity.signaturePublicKey))))
          return sendSignatureError(reply);
      }

      await prisma.$transaction([
        prisma.councilReshareKey.deleteMany({ where: { sessionId: session.id, helperSlot: member.slot } }),
        prisma.councilReshareKey.createMany({
          data: request.body.keys.map((k) => ({
            sessionId: session.id,
            helperSlot: member.slot,
            recipientSlot: k.recipient_slot,
            wrappedTransferKey: k.wrapped_transfer_key,
            signature: Buffer.from(base64ToUint8(k.binding_signature)),
          })),
        }),
        // New keys make earlier sub-shares of this helper unreadable.
        prisma.councilSubShare.deleteMany({ where: { sessionId: session.id, helperSlot: member.slot } }),
        prisma.councilReshareCommitment.deleteMany({ where: { sessionId: session.id, helperSlot: member.slot } }),
      ]);

      return { stored: request.body.keys.length };
    }
  );

  // A helper's sub-shares for a batch of escrows. Once every helper sealed theirs
  // for an escrow, it moves: new capsules for the target's custodians, the old
  // ones deleted, so a departed custodian's share stops matching anything.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/councils/reshare/:sessionId/sub-shares',
    {
      schema: {
        params: z.object({ sessionId: z.string().uuid() }),
        body: CouncilReshareSubSharesBodySchema,
        response: { 200: z.object({ moved: z.number().int(), remaining: z.number().int() }), ...errorResponses(400, 403) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const helper = await helperOf(request.params.sessionId, request.userId);
      if (!helper) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const { session, member, head, identity } = helper;
      if ((await prisma.councilReshareKey.count({ where: { sessionId: session.id, helperSlot: member.slot } })) === 0)
        return reply.status(400).send({ code: API_ERROR_COUNCIL_RESHARE_INVALID });

      const targetSlots = head.members.map((m) => m.slot).sort((a, b) => a - b);
      const escrowIds = request.body.escrows.map((e) => e.escrow_id);
      const known = await prisma.councilEscrow.findMany({
        where: { id: { in: escrowIds }, councilId: session.councilId, rosterVersionId: session.sourceRosterVersionId },
        select: { id: true, commitments: true },
      });
      if (known.length !== new Set(escrowIds).size) return reply.status(400).send({ code: API_ERROR_COUNCIL_RESHARE_INVALID });

      await ensureSodium();
      for (const entry of request.body.escrows) {
        const slots = entry.sub_shares.map((s) => s.recipient_slot).sort((a, b) => a - b);
        if (slots.length !== targetSlots.length || slots.some((slot, i) => slot !== targetSlots[i]))
          return reply.status(400).send({ code: API_ERROR_COUNCIL_RESHARE_INVALID });

        const commitmentBytes = base64ToUint8(entry.commitments);
        const signed = await verifyReshareCommitments(
          {
            sessionId: session.id,
            councilId: session.councilId,
            escrowId: entry.escrow_id,
            targetRosterVersion: head.version,
            helperSlot: member.slot,
            commitments: commitmentBytes,
          },
          base64ToUint8(entry.commitments_signature),
          new Uint8Array(identity.signaturePublicKey)
        );
        if (!signed) return sendSignatureError(reply);

        // The helper's split must start from its own share of the current one: a
        // vault that reshares a wrong share is stopped here, before anything moves.
        let consistent: boolean;
        try {
          const helperCommitments = decodeCommitments(commitmentBytes);
          const current = decodeCommitments(new Uint8Array(known.find((e) => e.id === entry.escrow_id)!.commitments));
          consistent =
            helperCommitments.length === head.threshold && checkHelperCommitments(current, member.slot, session.helperSlots, helperCommitments);
        } catch {
          consistent = false;
        }
        if (!consistent) {
          request.log.warn({ sessionId: session.id, escrowId: entry.escrow_id, helperSlot: member.slot }, 'council resharing commitments refused');
          return reply.status(400).send({ code: API_ERROR_COUNCIL_RESHARE_INVALID });
        }
      }

      await prisma.$transaction([
        prisma.councilSubShare.deleteMany({ where: { sessionId: session.id, helperSlot: member.slot, escrowId: { in: escrowIds } } }),
        prisma.councilReshareCommitment.deleteMany({ where: { sessionId: session.id, helperSlot: member.slot, escrowId: { in: escrowIds } } }),
        prisma.councilReshareCommitment.createMany({
          data: request.body.escrows.map((entry) => ({
            sessionId: session.id,
            escrowId: entry.escrow_id,
            helperSlot: member.slot,
            commitments: Buffer.from(base64ToUint8(entry.commitments)),
            signature: Buffer.from(base64ToUint8(entry.commitments_signature)),
          })),
        }),
        prisma.councilSubShare.createMany({
          data: request.body.escrows.flatMap((entry) =>
            entry.sub_shares.map((s) => ({
              sessionId: session.id,
              escrowId: entry.escrow_id,
              helperSlot: member.slot,
              recipientSlot: s.recipient_slot,
              sealed: s.sealed,
            }))
          ),
        }),
      ]);

      let moved = 0;
      for (const escrowId of escrowIds) {
        if (await moveEscrowIfComplete(session.id, escrowId)) moved++;
      }

      const progress = await reshareProgress(session.id, member.slot);
      if (progress.remaining === 0) {
        await prisma.councilReshareSession.update({ where: { id: session.id }, data: { status: 'completed', closedAt: new Date() } });
      }

      return { moved, remaining: progress.remaining };
    }
  );

  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/councils/reshare/:sessionId/cancel',
    {
      schema: {
        params: z.object({ sessionId: z.string().uuid() }),
        response: { 200: z.object({ cancelled: z.boolean() }), ...errorResponses(403, 404) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const session = await prisma.councilReshareSession.findUnique({ where: { id: request.params.sessionId } });
      if (!session || session.status !== 'open') return reply.status(404).send({ code: API_ERROR_COUNCIL_NOT_FOUND });
      if (!(await custodianOf(session.councilId, request.userId))) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      await prisma.$transaction([
        prisma.councilSubShare.deleteMany({ where: { sessionId: session.id } }),
        prisma.councilReshareCommitment.deleteMany({ where: { sessionId: session.id } }),
        prisma.councilReshareKey.deleteMany({ where: { sessionId: session.id } }),
        prisma.councilReshareSession.update({ where: { id: session.id }, data: { status: 'cancelled', closedAt: new Date() } }),
      ]);

      return { cancelled: true };
    }
  );
}

/** A capsule as the custodian's vault receives it, resolving a resharing's sub-shares and signed transfer keys. */
async function capsuleWire(
  capsule: { slot: number; generation: number; wrappedShare: string | null; sessionId: string | null },
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

  return {
    kind: 'reshared',
    generation: capsule.generation,
    slot: capsule.slot,
    session_id: session.id,
    escrow_id: escrowId,
    target_roster_version: session.targetRosterVersion.version,
    helpers: session.helperSlots.map((helperSlot) => {
      const key = keys.find((k) => k.helperSlot === helperSlot)!;
      const subShare = subShares.find((s) => s.helperSlot === helperSlot)!;
      const committed = commitments.find((c) => c.helperSlot === helperSlot)!;
      const helper = session.sourceRosterVersion.members.find((m) => m.slot === helperSlot)!;

      return {
        helper_slot: helperSlot,
        helper_identity_public_key: uint8ToBase64(new Uint8Array(helper.identity.signaturePublicKey)),
        wrapped_transfer_key: key.wrappedTransferKey,
        binding_signature: uint8ToBase64(new Uint8Array(key.signature)),
        sealed_sub_share: subShare.sealed,
        commitments: uint8ToBase64(new Uint8Array(committed.commitments)),
        commitments_signature: uint8ToBase64(new Uint8Array(committed.signature)),
      };
    }),
  };
}

/** Move one escrow to the session's target once every helper sealed its sub-shares for it. */
async function moveEscrowIfComplete(sessionId: string, escrowId: string): Promise<boolean> {
  return prisma.$transaction(
    async (tx) => {
      const session = await tx.councilReshareSession.findUniqueOrThrow({
        where: { id: sessionId },
        include: { targetRosterVersion: { include: { members: true } } },
      });
      const escrow = await tx.councilEscrow.findUnique({ where: { id: escrowId } });
      if (!escrow || escrow.rosterVersionId !== session.sourceRosterVersionId) return false;

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
      // The sub-shares of earlier resharings fed capsules that no longer exist.
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
    },
    { isolationLevel: 'Serializable' }
  );
}

// ----- Escrow submissions (enrollment, re-enrollment, re-arm after a recovery) ---

export type EscrowCheck =
  | { ok: true; head: RosterVersionRow; identityKey: Uint8Array; record: CouncilEscrowRecord }
  | { ok: false; status: 400 | 404 | 409; code: string };

/**
 * Check a submitted escrow against the head of its council: one capsule per
 * custodian of the head, its threshold, the credential's auth verifier bound to
 * the user's identity, and the identity signature over the whole record.
 */
export async function checkEscrowSubmission(userId: string, body: CouncilEscrowBody): Promise<EscrowCheck> {
  const head = await councilHead(body.council_id);
  if (!head) return { ok: false, status: 404, code: API_ERROR_COUNCIL_NOT_FOUND };
  if (head.version !== body.roster_version || head.threshold !== body.threshold)
    return { ok: false, status: 409, code: API_ERROR_COUNCIL_ROSTER_CHANGED };

  const headSlots = head.members.map((m) => m.slot).sort((a, b) => a - b);
  const sentSlots = body.shares.map((s) => s.slot).sort((a, b) => a - b);
  if (sentSlots.length !== headSlots.length || sentSlots.some((slot, i) => slot !== headSlots[i]))
    return { ok: false, status: 409, code: API_ERROR_COUNCIL_ROSTER_CHANGED };

  if (!kdfParamsAllowed(body.credential.kdf_ops, body.credential.kdf_mem))
    return { ok: false, status: 400, code: API_ERROR_VAULT_KDF_PARAMS_INVALID };

  const identityKey = await activeIdentityWireKey(userId);
  if (!identityKey) return { ok: false, status: 404, code: API_ERROR_VAULT_NOT_FOUND };

  try {
    const authPublicKey = base64ToUint8(body.credential.auth_public_key);
    if (!(await verifyAuthPublicKeyBinding(authPublicKey, base64ToUint8(body.credential.auth_pub_sig), importPublicKeyFromBytes(identityKey))))
      return { ok: false, status: 400, code: API_ERROR_COUNCIL_ESCROW_INVALID };

    await ensureSodium();
    const shareCommitments = base64ToUint8(body.share_commitments);
    if (decodeCommitments(shareCommitments).length !== body.threshold) return { ok: false, status: 400, code: API_ERROR_COUNCIL_ESCROW_INVALID };

    const record: CouncilEscrowRecord = {
      userId,
      councilId: body.council_id,
      rosterVersion: head.version,
      rosterHash: await rosterHash(rosterRecordOf(head)),
      threshold: body.threshold,
      escrowCreatedAtMillis: body.escrow_created_at_millis,
      credentialAuthPublicKeyHash: sha256(authPublicKey),
      secretCommitment: base64ToUint8(body.secret_commitment),
      shareCommitments,
      shares: await Promise.all(body.shares.map(async (s) => ({ slot: s.slot, capsuleHash: await capsuleHash(base64ToUint8(s.wrapped_share)) }))),
    };

    if (!(await verifyEscrow(record, base64ToUint8(body.escrow_signature), identityKey)))
      return { ok: false, status: 400, code: API_ERROR_COUNCIL_ESCROW_INVALID };

    return { ok: true, head, identityKey, record };
  } catch {
    return { ok: false, status: 400, code: API_ERROR_COUNCIL_ESCROW_INVALID };
  }
}

/** Write a checked escrow: its dormant credential, the escrow row and one capsule per custodian. Returns the escrow id. */
export async function writeEscrow(
  tx: Prisma.TransactionClient,
  userId: string,
  vaultId: string,
  body: CouncilEscrowBody,
  checked: Extract<EscrowCheck, { ok: true }>
): Promise<string> {
  const credential = await tx.vaultCredential.create({
    data: {
      vaultId,
      type: 'council',
      wrappedVrk: body.credential.wrapped_vrk,
      authPublicKey: Buffer.from(base64ToUint8(body.credential.auth_public_key)),
      authPubSig: Buffer.from(base64ToUint8(body.credential.auth_pub_sig)),
      kdfOps: body.credential.kdf_ops,
      kdfMem: body.credential.kdf_mem,
      lang: body.credential.lang,
    },
  });

  const signedShares: SignedShareEntry[] = checked.record.shares.map((s) => ({ slot: s.slot, capsule_hash: uint8ToBase64(s.capsuleHash) }));

  const escrow = await tx.councilEscrow.create({
    data: {
      userId,
      councilId: body.council_id,
      credentialId: credential.id,
      rosterVersionId: checked.head.id,
      threshold: body.threshold,
      generation: 1,
      signedRosterVersionId: checked.head.id,
      signedThreshold: body.threshold,
      signedShares: signedShares as unknown as Prisma.InputJsonValue,
      signedCommitments: Buffer.from(checked.record.shareCommitments),
      commitments: Buffer.from(checked.record.shareCommitments),
      secretCommitment: Buffer.from(checked.record.secretCommitment),
      escrowSignature: Buffer.from(base64ToUint8(body.escrow_signature)),
      escrowCreatedAt: new Date(body.escrow_created_at_millis),
    },
  });

  await tx.councilCapsule.createMany({
    data: body.shares.map((s) => ({
      escrowId: escrow.id,
      generation: 1,
      slot: s.slot,
      identityId: checked.head.members.find((m) => m.slot === s.slot)!.identityId,
      wrappedShare: s.wrapped_share,
    })),
  });

  return escrow.id;
}
