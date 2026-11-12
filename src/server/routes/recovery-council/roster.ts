import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { verifyRosterSignature } from '@encryption/src/crypto/council';
import { base64ToUint8 } from '@encryption/src/crypto/encryption-backup';
import { prisma } from '@encryption/src/prisma/client';
import {
  absentCustodiansOf,
  activeIdentityIdsOf,
  configuredCouncils,
  councilAbsenceDays,
  councilChain,
  councilHead,
  councilLabel,
  councilProposal,
  desiredRoster,
  escrowHealth,
  escrowRecordWire,
  escrowsLostByChange,
  proposalProgress,
  rosterRecordOf,
  rosterVersionWire,
  serializable,
  sha256,
  teamReady,
} from '@encryption/src/server/council-core';
import { moveTargetOf } from '@encryption/src/server/council-escrow';
import { EscrowHealthSchema, escrowsOf, healthOf, healthWire } from '@encryption/src/server/council-requests-core';
import { custodianRequestCounts } from '@encryption/src/server/council-requests-list';
import { activateIfReady, reshareProgress } from '@encryption/src/server/council-reshare-core';
import { env } from '@encryption/src/server/env';
import { errorResponses } from '@encryption/src/server/error-response';
import { configuredCouncil, councilForEmail } from '@encryption/src/server/recovery-councils';
import { sendSignatureError } from '@encryption/src/server/routes/recovery-council/replies';
import { SKIP_SIG, STEP_UP, assertUserId } from '@encryption/src/server/routes/transport-auth';
import { userFullName } from '@encryption/src/server/user-name';
import {
  API_ERROR_COUNCIL_NOT_CUSTODIAN,
  API_ERROR_COUNCIL_NOT_FOUND,
  API_ERROR_COUNCIL_ROSTER_CHANGED,
  API_ERROR_VAULT_NOT_FOUND,
} from '@encryption/src/shared/error-codes';
import { CouncilEscrowRecordWireSchema, RosterVersionWireSchema } from '@encryption/src/shared/schemas/recovery-council';

export function rosterRoutes(app: FastifyInstance): void {
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
                // Out of the configuration: the configured council its people are offered to move to, if any.
                replaced_by: z.string().nullable(),
                my_slot: z.number().int().nullable(),
                chain: z.array(RosterVersionWireSchema),
                proposal: z
                  .object({
                    roster: RosterVersionWireSchema,
                    quorum_missing: z.number().int().nonnegative(),
                    pending_members: z.array(z.object({ slot: z.number().int(), name: z.string() })),
                    // Escrows recoverable today that this change would make unrecoverable.
                    escrows_lost: z.number().int().nonnegative(),
                    signed_by_me: z.boolean(),
                    may_sign: z.boolean(),
                  })
                  .nullable(),
                blocked: z.array(
                  z.object({
                    email: z.string(),
                    name: z.string().nullable(),
                    member: z.boolean(),
                    reason: z.enum(['unknown-user', 'email-mismatch', 'not-onboarded']),
                  })
                ),
                health: z.object({
                  escrows: z.number().int().nonnegative(),
                  ok: z.number().int().nonnegative(),
                  at_risk: z.number().int().nonnegative(),
                  lost: z.number().int().nonnegative(),
                  // Who to tell: the people whose vault in use the team can no longer give back.
                  lost_names: z.array(z.string()),
                  outdated: z.array(z.object({ version: z.number().int(), escrows: z.number().int() })),
                  // Custodians of the head with no sign-in for `absence_days`: their shares still count, the margin does not.
                  absent: z.array(z.string()),
                  absence_days: z.number().int().positive(),
                  // Every custodian of the head has an active identity: people can join, so the lost ones can be told to.
                  team_ready: z.boolean(),
                }),
                // Live recovery requests, and those this custodian can act on; the list itself is paged (`/api/councils/:councilId/requests`).
                requests_count: z.number().int().nonnegative(),
                requests_to_handle: z.number().int().nonnegative(),
                // Reshared shares this custodian's vault has not checked yet, and
                // those found invalid across the council, by the helper that sent them.
                shares_to_check: z.number().int().nonnegative(),
                faulty_reshares: z.array(z.object({ helper_name: z.string(), escrows: z.number().int().positive() })),
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
      const now = Date.now();

      const memberships = await prisma.councilRosterMember.findMany({
        where: { userId, rosterVersion: { status: { in: ['active', 'proposed'] } } },
        include: { rosterVersion: true },
      });
      const councilIds = [...new Set(memberships.map((m) => m.rosterVersion.councilId))];
      const myIdentity = await prisma.identity.findFirst({ where: { userId, disabledAt: null }, orderBy: { generation: 'desc' } });

      const result = [];

      for (const councilId of councilIds) {
        const [head, proposal, chain] = await Promise.all([councilHead(councilId), councilProposal(councilId), councilChain(councilId)]);
        const myHeadMember = head?.members.find((m) => m.userId === userId) ?? null;
        const role = myHeadMember ? ('custodian' as const) : ('invited' as const);
        const config = configuredCouncil(configuredCouncils(), councilId);
        // Closed: out of the configuration and protecting nobody (a request needs an escrow). It comes back with its chain if configured again.
        if (!config && (await prisma.councilEscrow.count({ where: { councilId } })) === 0) continue;

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
            escrows_lost: head ? await escrowsLostByChange(head, proposal) : 0,
            signed_by_me: proposal.signatures.some((s) => s.identityId === myIdentity?.id),
            may_sign: inProposal || inHead,
          };
        }

        // Health and requests are a custodian's business, not an invitee's.
        const health = {
          escrows: 0,
          ok: 0,
          at_risk: 0,
          lost: 0,
          lost_names: [] as string[],
          outdated: [] as Array<{ version: number; escrows: number }>,
          absent: [] as string[],
          absence_days: councilAbsenceDays(councilId),
          team_ready: true,
        };
        let requestsCount = 0;
        let requestsToHandle = 0;
        let reshare = null;
        let sharesToCheck = 0;
        let replacedBy: string | null = null;
        const faultyReshares: Array<{ helper_name: string; escrows: number }> = [];

        if (myHeadMember && head) {
          const escrows = await prisma.councilEscrow.findMany({
            where: { councilId },
            include: { capsules: true, rosterVersion: true, user: true, credential: { include: { vault: true } } },
          });
          const active = await activeIdentityIdsOf([...new Set(escrows.flatMap((e) => e.capsules.map((c) => c.identityId)))]);
          const absent = await absentCustodiansOf(head);
          const outdated = new Map<number, number>();
          health.absent = head.members.filter((m) => absent.has(m.userId)).map((m) => userFullName(m.user) ?? m.user.email);
          health.team_ready = await teamReady(head);

          if (!config) {
            for (const escrow of escrows) {
              const target = councilForEmail(configuredCouncils(), escrow.user.email);
              if (target && target.id !== councilId && (await councilHead(target.id))) {
                replacedBy = target.label;
                break;
              }
            }
          }

          for (const escrow of escrows) {
            const h = escrowHealth(escrow, head, active, absent);
            health.escrows++;
            if (h.status === 'ok') health.ok++;
            else if (h.status === 'at-risk') health.at_risk++;
            else {
              health.lost++;
              if (escrow.credential.vault.disabledAt === null) health.lost_names.push(userFullName(escrow.user) ?? escrow.user.email);
            }
            if (h.outdated) outdated.set(escrow.rosterVersion.version, (outdated.get(escrow.rosterVersion.version) ?? 0) + 1);
          }
          health.outdated = [...outdated.entries()].sort(([a], [b]) => a - b).map(([version, count]) => ({ version, escrows: count }));

          sharesToCheck = escrows.filter((e) =>
            e.capsules.some(
              (c) => c.slot === myHeadMember.slot && c.identityId === myHeadMember.identityId && c.sessionId !== null && c.checkedAt === null
            )
          ).length;

          const faulty = new Map<string, { sessionId: string; slot: number | null; escrows: number }>();
          for (const escrow of escrows) {
            for (const capsule of escrow.capsules.filter((c) => c.invalid && c.sessionId !== null)) {
              const key = `${capsule.sessionId}|${capsule.faultyHelperSlot ?? ''}`;
              const entry = faulty.get(key) ?? { sessionId: capsule.sessionId!, slot: capsule.faultyHelperSlot, escrows: 0 };
              entry.escrows++;
              faulty.set(key, entry);
            }
          }
          const sessions = await prisma.councilReshareSession.findMany({
            where: { id: { in: [...new Set([...faulty.values()].map((f) => f.sessionId))] } },
            include: { sourceRosterVersion: { include: { members: { include: { user: true } } } } },
          });
          for (const entry of faulty.values()) {
            const session = sessions.find((s) => s.id === entry.sessionId);
            const member = entry.slot !== null ? session?.sourceRosterVersion.members.find((m) => m.slot === entry.slot) : undefined;
            faultyReshares.push({ helper_name: member ? (userFullName(member.user) ?? member.user.email) : '?', escrows: entry.escrows });
          }

          const counts = await custodianRequestCounts(councilId, head, myHeadMember, now);
          requestsCount = counts.all;
          requestsToHandle = counts['to-handle'];

          const session = await prisma.councilReshareSession.findFirst({
            where: { councilId, status: 'open' },
            include: { sourceRosterVersion: true, targetRosterVersion: true },
          });
          if (session) {
            const progress = await reshareProgress(session.id, myHeadMember.slot);
            reshare = {
              session_id: session.id,
              source_version: session.sourceRosterVersion.version,
              target_version: session.targetRosterVersion.version,
              helper_slots: session.helperSlots,
              i_am_helper: session.helperSlots.includes(myHeadMember.slot),
              remaining_for_me: progress.remainingForMe,
              remaining: progress.remaining,
            };
          }
        }

        result.push({
          council_id: councilId,
          label: await councilLabel(councilId),
          role,
          configured: config !== null,
          replaced_by: replacedBy,
          my_slot: myHeadMember?.slot ?? null,
          chain: chain.map(rosterVersionWire),
          proposal: proposalWire,
          blocked: config
            ? (await desiredRoster(config)).blocked.map((b) => ({
                email: b.email,
                name: b.name,
                member: head?.members.some((m) => m.userId === b.userId) ?? false,
                reason: b.reason,
              }))
            : [],
          health,
          requests_count: requestsCount,
          requests_to_handle: requestsToHandle,
          reshare,
          shares_to_check: sharesToCheck,
          faulty_reshares: faultyReshares,
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
                // Joining (again) works only once every custodian of the head has encryption set up.
                team_ready: z.boolean(),
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
            // The council the user's email maps to now, when another one holds their escrow and this one is in force.
            move_to: z
              .object({
                council_id: z.string(),
                label: z.string(),
                configured: z.boolean(),
                chain: z.array(RosterVersionWireSchema),
                team_ready: z.boolean(),
              })
              .nullable(),
            // The vault in use, escrowed or not: what giving back an older one would put aside.
            active_vault_created_at_millis: z.number().int().nullable(),
            // Every vault a council can still give back, the current one first: older ones may stay with a previous council.
            vaults: z.array(
              z.object({
                escrow_id: z.string().uuid(),
                council_label: z.string(),
                active: z.boolean(),
                created_at_millis: z.number().int(),
                disabled_at_millis: z.number().int().nullable(),
              })
            ),
          }),
        },
      },
    },
    async (request) => {
      assertUserId(request);
      const userId = request.userId;

      const user = await prisma.user.findUnique({ where: { id: userId } });
      const escrows = await escrowsOf(userId);
      const escrow = escrows[0] ?? null;
      const councilId = escrow?.councilId ?? (user ? councilForEmail(configuredCouncils(), user.email)?.id : undefined);

      let council = null;
      if (councilId) {
        const chain = await councilChain(councilId);
        council =
          chain.length > 0
            ? {
                council_id: councilId,
                label: await councilLabel(councilId),
                configured: configuredCouncil(configuredCouncils(), councilId) !== null,
                chain: chain.map(rosterVersionWire),
                team_ready: await teamReady((await councilHead(councilId))!),
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

      const vaults = [];
      for (const e of escrows) {
        if ((await healthOf(e)).status === 'lost') continue;
        vaults.push({
          escrow_id: e.id,
          council_label: await councilLabel(e.councilId),
          active: e.credential.vault.disabledAt === null,
          created_at_millis: e.credential.vault.createdAt.getTime(),
          disabled_at_millis: e.credential.vault.disabledAt?.getTime() ?? null,
        });
      }

      const active = await prisma.vaultKeyring.findFirst({ where: { userId, disabledAt: null }, select: { createdAt: true } });

      const moveTarget = await moveTargetOf(userId);
      const moveTo = moveTarget
        ? {
            council_id: moveTarget,
            label: await councilLabel(moveTarget),
            configured: true,
            chain: (await councilChain(moveTarget)).map(rosterVersionWire),
            team_ready: await teamReady((await councilHead(moveTarget))!),
          }
        : null;

      return { council, escrow: escrowWire, move_to: moveTo, active_vault_created_at_millis: active?.createdAt.getTime() ?? null, vaults };
    }
  );

  // A custodian (or someone a proposal adds) signs a roster version. Their vault
  // signed the exact payload rebuilt from what they were shown; the server checks
  // it against the same payload rebuilt from the database, so a version that
  // changed in between is refused rather than signed blind.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/councils/:councilId/versions/:version/sign',
    {
      ...STEP_UP,
      schema: {
        params: z.object({ councilId: z.string().min(1).max(64), version: z.coerce.number().int().positive() }),
        body: z.object({ signature: z.string().min(1).max(1024) }),
        response: { 200: z.object({ activated: z.boolean() }), ...errorResponses(400, 401, 403, 404, 409) },
      },
    },
    async (request, reply) => {
      assertUserId(request);

      const userId = request.userId;
      const { councilId } = request.params;
      const proposal = await councilProposal(councilId);
      if (!proposal) return reply.status(404).send({ code: API_ERROR_COUNCIL_NOT_FOUND });
      if (proposal.version !== request.params.version) return reply.status(409).send({ code: API_ERROR_COUNCIL_ROSTER_CHANGED });

      const identity = await prisma.identity.findFirst({ where: { userId, disabledAt: null }, orderBy: { generation: 'desc' } });
      if (!identity) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

      const head = await councilHead(councilId);
      const mayVouch = proposal.members.some((m) => m.userId === userId && m.identityId === identity.id);
      const mayApprove = head?.members.some((m) => m.userId === userId && m.identityId === identity.id) ?? false;
      if (!mayVouch && !mayApprove) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const signature = base64ToUint8(request.body.signature);
      if (!(await verifyRosterSignature(rosterRecordOf(proposal), signature, new Uint8Array(identity.signaturePublicKey))))
        return sendSignatureError(reply);

      // The proposal may have been replaced (a sync) or activated since it was read.
      const stored = await serializable(async (tx) => {
        const current = await tx.councilRosterVersion.findUnique({ where: { id: proposal.id } });
        if (current?.status !== 'proposed') return false;

        await tx.councilRosterSignature.upsert({
          where: { rosterVersionId_identityId: { rosterVersionId: proposal.id, identityId: identity.id } },
          create: { rosterVersionId: proposal.id, identityId: identity.id, signature: Buffer.from(signature) },
          update: { signature: Buffer.from(signature) },
        });

        return true;
      });
      if (!stored) return reply.status(409).send({ code: API_ERROR_COUNCIL_ROSTER_CHANGED });

      const activated = await activateIfReady(councilId);

      return { activated: activated !== null };
    }
  );
}
