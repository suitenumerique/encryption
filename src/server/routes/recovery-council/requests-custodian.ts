import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { type ContributionRecord, ephemeralKeyHash, verifyContribution, wrappedSharesHash } from '@encryption/src/crypto/council';
import { base64ToUint8, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import type { Prisma } from '@encryption/src/generated/prisma/client';
import { prisma } from '@encryption/src/prisma/client';
import { requireStepUp } from '@encryption/src/server/auth/step-up';
import { councilChain, councilLabel, custodianOf, escrowRecordWire, rosterVersionWire, sha256 } from '@encryption/src/server/council-core';
import {
  type RequestStage,
  RequestStageSchema,
  closeRequest,
  liveSlots,
  lockRequest,
  settleLocked,
  settleRequest,
} from '@encryption/src/server/council-requests-core';
import { afterRequestClosed, capsuleWire } from '@encryption/src/server/council-reshare-core';
import { sendCouncilRecoveryAborted, sendCouncilRecoveryToApprove } from '@encryption/src/server/email/council';
import { env } from '@encryption/src/server/env';
import { errorResponses } from '@encryption/src/server/error-response';
import { emergencyRecipient } from '@encryption/src/server/routes/emergency-core';
import { logEmailFailure, sendSignatureError } from '@encryption/src/server/routes/recovery-council/replies';
import { isRetryableRegistrationError } from '@encryption/src/server/routes/registration-core';
import { SKIP_SIG, assertUserId } from '@encryption/src/server/routes/transport-auth';
import { userFullName } from '@encryption/src/server/user-name';
import {
  API_ERROR_COUNCIL_ALREADY_CONTRIBUTED,
  API_ERROR_COUNCIL_MEETING_FIRST,
  API_ERROR_COUNCIL_NOT_CUSTODIAN,
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
        include: { user: true, escrow: { include: { capsules: true, credential: true, signedRosterVersion: true } } },
      });
      if (!row) return reply.status(404).send({ code: API_ERROR_COUNCIL_REQUEST_NOT_FOUND });

      const custodian = await custodianOf(row.escrow.councilId, request.userId);
      if (!custodian) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });
      if (row.userId === request.userId) return reply.status(403).send({ code: API_ERROR_COUNCIL_OWN_REQUEST });

      const settled = (await settleRequest(row.id, Date.now()))!;
      if (settled.stage !== 'collecting' && settled.stage !== 'awaiting_meeting')
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
        escrow: escrowRecordWire(row.escrow, sha256(new Uint8Array(row.escrow.credential.authPublicKey))),
        capsule: await capsuleWire(capsule, row.escrowId),
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
      if (row.userId === request.userId) return reply.status(403).send({ code: API_ERROR_COUNCIL_OWN_REQUEST });

      const custodian = await custodianOf(row.escrow.councilId, request.userId);
      if (!custodian || custodian.member.slot !== body.slot) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

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

      const now = Date.now();
      let outcome: ContributeOutcome;
      try {
        outcome = await prisma.$transaction(async (tx): Promise<ContributeOutcome> => {
          if (!(await lockRequest(tx, row.id))) return { ok: false, status: 404, code: API_ERROR_COUNCIL_REQUEST_NOT_FOUND };

          // Under the lock: the escrow may have moved and the roster changed since the reads above.
          const escrow = await tx.councilEscrow.findUniqueOrThrow({ where: { id: row.escrowId }, include: { capsules: true } });
          const member = await custodianOf(escrow.councilId, request.userId, tx);
          if (!member || member.member.slot !== body.slot || !custodianCapsule(escrow.capsules, escrow.generation, member.member, member.identity.id))
            return { ok: false, status: 403, code: API_ERROR_COUNCIL_NOT_CUSTODIAN };

          const before = await settleLocked(tx, row.id, now);
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
        if (outcome.closed) await afterRequestClosed(row.escrowId);
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
              council: councilLabel(outcome.escrow.councilId),
              step: 'approve',
              productUrl,
            }).catch(logEmailFailure(app, 'to approve'));
        }
      }

      return { stage: outcome.after };
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

      const aborted = await closeRequest(row.id);

      if (aborted) {
        const user = await emergencyRecipient(row.userId);
        if (user)
          sendCouncilRecoveryAborted({ recipient: user.email, locale: user.locale, council: councilLabel(row.escrow.councilId) }).catch(
            logEmailFailure(app, 'aborted')
          );
      }

      return { aborted };
    }
  );
}
