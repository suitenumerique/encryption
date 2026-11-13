import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { type ContributionRecord, ephemeralKeyHash, verifyContribution, wrappedSharesHash } from '@encryption/src/crypto/council';
import { base64ToUint8, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import type { Prisma } from '@encryption/src/generated/prisma/client';
import { prisma } from '@encryption/src/prisma/client';
import {
  councilChain,
  councilHead,
  councilLabel,
  custodianOf,
  escrowRecordWire,
  rosterVersionWire,
  sha256,
} from '@encryption/src/server/council-core';
import {
  type RequestStage,
  RequestStageSchema,
  closeRequest,
  liveSlots,
  lockRequest,
  settleLocked,
  settleRequest,
} from '@encryption/src/server/council-requests-core';
import { RequestFilterSchema, custodianRequestCounts, custodianRequestPage } from '@encryption/src/server/council-requests-list';
import { afterRequestClosed, capsuleWire } from '@encryption/src/server/council-reshare-core';
import { notifyReadyRequest, scheduleReadyNotice } from '@encryption/src/server/council-sync';
import { sendCouncilRecoveryAborted, sendCouncilRecoveryToApprove } from '@encryption/src/server/email/council';
import { env } from '@encryption/src/server/env';
import { errorResponses } from '@encryption/src/server/error-response';
import { emergencyRecipient } from '@encryption/src/server/routes/emergency-core';
import { logEmailFailure, sendSignatureError } from '@encryption/src/server/routes/recovery-council/replies';
import { isRetryableRegistrationError } from '@encryption/src/server/routes/registration-core';
import { SKIP_SIG, STEP_UP, assertUserId } from '@encryption/src/server/routes/transport-auth';
import { userFullName } from '@encryption/src/server/user-name';
import { REQUEST_FILTERS, REQUEST_PAGE_SIZES, type RequestFilter } from '@encryption/src/shared/council-request-filters';
import {
  API_ERROR_COUNCIL_ALREADY_CONTRIBUTED,
  API_ERROR_COUNCIL_ENOUGH_SHARES,
  API_ERROR_COUNCIL_MEETING_FIRST,
  API_ERROR_COUNCIL_NOT_CUSTODIAN,
  API_ERROR_COUNCIL_NOT_FOUND,
  API_ERROR_COUNCIL_OWN_REQUEST,
  API_ERROR_COUNCIL_REQUEST_CLOSED,
  API_ERROR_COUNCIL_REQUEST_NOT_FOUND,
} from '@encryption/src/shared/error-codes';
import {
  CouncilAttestationWireSchema,
  CouncilCapsuleWireSchema,
  CouncilContributionBodySchema,
  CouncilEscrowRecordWireSchema,
  RosterVersionWireSchema,
} from '@encryption/src/shared/schemas/recovery-council';

type ContributeOutcome =
  | { ok: false; status: 400 | 403 | 404 | 409; code: string; closed?: boolean }
  | {
      ok: true;
      before: RequestStage;
      after: RequestStage;
      contributed: Set<number>;
      escrow: Prisma.CouncilEscrowGetPayload<{ include: { capsules: true } }>;
    };

/** The capsule a custodian hands over from: their slot, the escrow's current split, their key, not found invalid. */
function custodianCapsule<C extends { slot: number; generation: number; identityId: string; invalid: boolean }>(
  capsules: C[],
  generation: number,
  member: { slot: number },
  identityId: string
): C | undefined {
  return capsules.find((c) => c.slot === member.slot && c.generation === generation && c.identityId === identityId && !c.invalid);
}

export function custodianRequestRoutes(app: FastifyInstance): void {
  const productUrl = env.EMAIL_PRODUCT_URL ?? '';

  // A council's live requests, one page at a time, for one of its custodians:
  // the filter, the search and the order are applied here, so a council with
  // many requests never sends them all.
  app.withTypeProvider<ZodTypeProvider>().get(
    '/api/councils/:councilId/requests',
    {
      ...SKIP_SIG,
      schema: {
        params: z.object({ councilId: z.string().min(1) }),
        querystring: z.object({
          page: z.coerce.number().int().positive().default(1),
          page_size: z.coerce
            .number()
            .int()
            .refine((size) => (REQUEST_PAGE_SIZES as readonly number[]).includes(size))
            .default(REQUEST_PAGE_SIZES[0]),
          filter: RequestFilterSchema.default('all'),
          query: z.string().max(200).default(''),
        }),
        response: {
          200: z.object({
            items: z.array(
              z.object({
                id: z.string().uuid(),
                user_name: z.string().nullable(),
                user_email: z.string(),
                created_at_millis: z.number().int(),
                expires_at_millis: z.number().int(),
                stage: RequestStageSchema,
                contributors: z.array(z.object({ slot: z.number().int(), name: z.string(), in_person: z.boolean() })),
                threshold: z.number().int().positive(),
                my_contribution: z.enum(['none', 'remote', 'in_person']),
                can_contribute: z.boolean(),
                holds_part: z.boolean(),
              })
            ),
            // Matching the filter and the search, across every page.
            total_count: z.number().int().nonnegative(),
            // Per filter, before the search: what the filter menu offers.
            counts: z.object(
              Object.fromEntries(REQUEST_FILTERS.map((f) => [f, z.number().int().nonnegative()])) as Record<RequestFilter, z.ZodNumber>
            ),
          }),
          ...errorResponses(404),
        },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const { page, page_size: pageSize, filter, query } = request.query;
      const head = await councilHead(request.params.councilId);
      const me = head?.members.find((m) => m.userId === request.userId);
      if (!head || !me) return reply.status(404).send({ code: API_ERROR_COUNCIL_NOT_FOUND });

      const now = Date.now();
      const { items, total } = await custodianRequestPage(head.councilId, head, me, now, { filter, query, page, pageSize });

      return { items, total_count: total, counts: await custodianRequestCounts(head.councilId, head, me, now) };
    }
  );

  // What a custodian's vault needs to hand over their share: the request's
  // ephemeral key, the user's signed escrow record, their own capsule, and the
  // council's chain the vault verifies the helpers of a reshared capsule against.
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
            // The identity the escrow's vault was created under, which signed it: not the current one for an earlier vault.
            owner_identity_public_key: z.string(),
            escrow: CouncilEscrowRecordWireSchema,
            capsule: CouncilCapsuleWireSchema,
            chain: z.array(RosterVersionWireSchema),
            // The share handed over at the meeting, signed: what a remote
            // custodian's vault checks before releasing anything to this key.
            attestation: CouncilAttestationWireSchema.nullable(),
          }),
          ...errorResponses(400, 403, 404),
        },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const row = await prisma.councilRequest.findUnique({
        where: { id: request.params.id },
        include: {
          user: true,
          escrow: { include: { capsules: true, credential: { include: { vault: { include: { identity: true } } } }, signedRosterVersion: true } },
        },
      });
      if (!row) return reply.status(404).send({ code: API_ERROR_COUNCIL_REQUEST_NOT_FOUND });

      const custodian = await custodianOf(row.councilId, request.userId);
      if (!custodian) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });
      if (row.userId === request.userId) return reply.status(403).send({ code: API_ERROR_COUNCIL_OWN_REQUEST });

      const settled = (await settleRequest(row.id, Date.now()))!;
      if (!row.escrow || (settled.stage !== 'collecting' && settled.stage !== 'awaiting_meeting'))
        return reply.status(400).send({ code: API_ERROR_COUNCIL_REQUEST_CLOSED });

      const capsule = custodianCapsule(row.escrow.capsules, row.escrow.generation, custodian.member, custodian.identity.id);
      if (!capsule) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const attestation = await prisma.councilContribution.findFirst({
        where: { requestId: row.id, inPerson: true },
        include: { custodianIdentity: true },
        orderBy: { createdAt: 'asc' },
      });

      return {
        id: row.id,
        council_id: row.escrow.councilId,
        user_id: row.userId,
        user_name: userFullName(row.user),
        user_email: row.user.email,
        ephemeral_public_key: uint8ToBase64(new Uint8Array(row.ephemeralPublicKey)),
        stage: settled.stage,
        meeting_required: settled.stage === 'awaiting_meeting',
        owner_identity_public_key: uint8ToBase64(new Uint8Array(row.escrow.credential.vault.identity.signaturePublicKey)),
        escrow: escrowRecordWire(row.escrow, sha256(new Uint8Array(row.escrow.credential.authPublicKey))),
        capsule: await capsuleWire(capsule, row.escrow.id),
        chain: (await councilChain(row.escrow.councilId)).map(rosterVersionWire),
        attestation: attestation
          ? {
              slot: attestation.slot,
              custodian_user_id: attestation.custodianIdentity.userId,
              wrapped_share: attestation.wrappedShare,
              signature: uint8ToBase64(new Uint8Array(attestation.signature)),
            }
          : null,
      };
    }
  );

  // Hand over one share. Identity-signed with a fresh authentication. The first
  // share is always one a custodian handed over after checking the code on the
  // person's own screen; remote approvals come after it, and their vaults release
  // nothing to a key that share does not attest. The checks and the insert run
  // under a lock on the request, so a share never lands after a refusal.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/council-recovery/requests/:id/contribute',
    {
      ...STEP_UP,
      schema: {
        params: z.object({ id: z.string().uuid() }),
        body: CouncilContributionBodySchema,
        response: { 200: z.object({ stage: RequestStageSchema }), ...errorResponses(400, 401, 403, 404, 409) },
      },
    },
    async (request, reply) => {
      assertUserId(request);

      const body = request.body;
      const row = await prisma.councilRequest.findUnique({ where: { id: request.params.id } });
      if (!row) return reply.status(404).send({ code: API_ERROR_COUNCIL_REQUEST_NOT_FOUND });
      if (row.userId === request.userId) return reply.status(403).send({ code: API_ERROR_COUNCIL_OWN_REQUEST });

      const custodian = await custodianOf(row.councilId, request.userId);
      if (!custodian || custodian.member.slot !== body.slot) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const record: ContributionRecord = {
        requestId: row.id,
        userId: row.userId,
        councilId: row.councilId,
        slot: body.slot,
        custodianUserId: request.userId,
        ephemeralPublicKeyHash: await ephemeralKeyHash(new Uint8Array(row.ephemeralPublicKey)),
        wrappedSharesHash: await wrappedSharesHash([base64ToUint8(body.wrapped_share)]),
        inPerson: body.in_person,
      };
      const signature = base64ToUint8(body.signature);
      if (!(await verifyContribution(record, signature, new Uint8Array(custodian.identity.signaturePublicKey)))) return sendSignatureError(reply);

      const now = Date.now();
      let outcome: ContributeOutcome;
      try {
        outcome = await prisma.$transaction(async (tx): Promise<ContributeOutcome> => {
          if (!(await lockRequest(tx, row.id))) return { ok: false, status: 404, code: API_ERROR_COUNCIL_REQUEST_NOT_FOUND };

          // Under the lock: the escrow may have moved (or been burned) and the roster changed since the reads above.
          const locked = await tx.councilRequest.findUniqueOrThrow({ where: { id: row.id }, select: { escrowId: true } });
          if (!locked.escrowId) return { ok: false, status: 400, code: API_ERROR_COUNCIL_REQUEST_CLOSED };
          const escrow = await tx.councilEscrow.findUniqueOrThrow({ where: { id: locked.escrowId }, include: { capsules: true } });
          const member = await custodianOf(escrow.councilId, request.userId, tx);
          if (!member || member.member.slot !== body.slot || !custodianCapsule(escrow.capsules, escrow.generation, member.member, member.identity.id))
            return { ok: false, status: 403, code: API_ERROR_COUNCIL_NOT_CUSTODIAN };

          const before = await settleLocked(tx, row.id, now);
          // Enough shares are already in: a late one would add nothing.
          if (before.stage === 'cooldown' || before.stage === 'released') return { ok: false, status: 409, code: API_ERROR_COUNCIL_ENOUGH_SHARES };
          if (before.stage !== 'collecting' && before.stage !== 'awaiting_meeting')
            return { ok: false, status: 400, code: API_ERROR_COUNCIL_REQUEST_CLOSED, closed: before.closed };
          if ((await tx.councilContribution.count({ where: { requestId: row.id, slot: body.slot } })) > 0)
            return { ok: false, status: 409, code: API_ERROR_COUNCIL_ALREADY_CONTRIBUTED };

          if (!body.in_person && before.stage === 'awaiting_meeting') return { ok: false, status: 409, code: API_ERROR_COUNCIL_MEETING_FIRST };

          await tx.councilContribution.create({
            data: {
              requestId: row.id,
              slot: body.slot,
              custodianIdentityId: member.identity.id,
              wrappedShare: body.wrapped_share,
              inPerson: body.in_person,
              signature: Buffer.from(signature),
            },
          });

          const after = await settleLocked(tx, row.id, now);

          return { ok: true, before: before.stage, after: after.stage, contributed: new Set(after.facts.contributions.map((c) => c.slot)), escrow };
        });
      } catch (err) {
        if (isRetryableRegistrationError(err)) return reply.status(409).send({ code: API_ERROR_COUNCIL_ALREADY_CONTRIBUTED });
        throw err;
      }

      if (!outcome.ok) {
        if (outcome.closed && row.escrowId) await afterRequestClosed(row.escrowId);
        return reply.status(outcome.status).send({ code: outcome.code });
      }

      // Met in person: the other custodians may now approve remotely.
      if (outcome.before === 'awaiting_meeting' && outcome.after === 'collecting') {
        const requester = await emergencyRecipient(row.userId);
        for (const { member } of await liveSlots(outcome.escrow)) {
          if (outcome.contributed.has(member.slot)) continue;
          const custodian = await emergencyRecipient(member.userId);
          if (custodian && requester)
            sendCouncilRecoveryToApprove({
              recipient: custodian.email,
              locale: custodian.locale,
              requester: requester.labelWithEmail,
              council: await councilLabel(outcome.escrow.councilId),
              step: 'approve',
              productUrl,
            }).catch(logEmailFailure(app, 'to approve'));
        }
      }

      // The last share needed: the user is told to go back to the browser that asked, now or when the cooldown ends.
      if (outcome.after === 'released') await notifyReadyRequest(row.id, app.log).catch(logEmailFailure(app, 'recovery ready'));
      if (outcome.after === 'cooldown' && outcome.before !== 'cooldown') scheduleReadyNotice(row.id, row.releaseNotBefore, app.log);

      return { stage: outcome.after };
    }
  );

  // A custodian stops a request they find suspicious. Identity-signed with a
  // fresh authentication: denying a recovery is the most it can do.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/council-recovery/requests/:id/abort',
    {
      ...STEP_UP,
      schema: {
        params: z.object({ id: z.string().uuid() }),
        response: { 200: z.object({ aborted: z.boolean() }), ...errorResponses(401, 403, 404) },
      },
    },
    async (request, reply) => {
      assertUserId(request);

      const row = await prisma.councilRequest.findUnique({ where: { id: request.params.id } });
      if (!row) return reply.status(404).send({ code: API_ERROR_COUNCIL_REQUEST_NOT_FOUND });
      if (!(await custodianOf(row.councilId, request.userId))) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const aborted = await closeRequest(row.id, 'aborted');

      if (aborted) {
        const user = await emergencyRecipient(row.userId);
        if (user)
          sendCouncilRecoveryAborted({ recipient: user.email, locale: user.locale, council: await councilLabel(row.councilId) }).catch(
            logEmailFailure(app, 'aborted')
          );
      }

      return { aborted };
    }
  );
}
