import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { requestFingerprint } from '@encryption/src/crypto/council';
import { base64ToUint8, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { prisma } from '@encryption/src/prisma/client';
import { configuredCouncils, councilLabel, escrowRecordWire, serializable, sha256 } from '@encryption/src/server/council-core';
import { closeRequest, escrowForRecovery, healthOf, liveSlots, openRequestOf, settleRequest } from '@encryption/src/server/council-requests-core';
import { sendCouncilRecoveryRequested, sendCouncilRecoveryToApprove } from '@encryption/src/server/email/council';
import { env } from '@encryption/src/server/env';
import { errorResponses } from '@encryption/src/server/error-response';
import { COUNCIL_DEFAULT_REQUEST_TTL_DAYS, configuredCouncil } from '@encryption/src/server/recovery-councils';
import { DAY_MS, emergencyRecipient } from '@encryption/src/server/routes/emergency-core';
import { logEmailFailure } from '@encryption/src/server/routes/recovery-council/replies';
import { isRetryableRegistrationError } from '@encryption/src/server/routes/registration-core';
import { SKIP_SIG, assertUserId } from '@encryption/src/server/routes/transport-auth';
import { userFullName } from '@encryption/src/server/user-name';
import {
  API_ERROR_COUNCIL_ESCROW_UNRECOVERABLE,
  API_ERROR_COUNCIL_NO_ESCROW,
  API_ERROR_COUNCIL_REQUEST_CLOSED,
  API_ERROR_COUNCIL_REQUEST_EXISTS,
  API_ERROR_COUNCIL_REQUEST_NOT_FOUND,
  API_ERROR_RATE_LIMIT_COUNCIL,
} from '@encryption/src/shared/error-codes';
import type { MnemonicLanguage } from '@encryption/src/shared/schemas/mnemonic-language';
import { CouncilReleasedSharesSchema } from '@encryption/src/shared/schemas/recovery-council';

// A recovery request emails the user and every custodian: a stolen login asking,
// refusing and asking again must not turn that into a mail cannon. Counted from
// the stored requests, so the limit holds across instances and restarts.
const REQUEST_RATE_LIMIT_WINDOW_MS = DAY_MS;
const REQUEST_RATE_LIMIT_MAX = 3;

export function userRequestRoutes(app: FastifyInstance): void {
  const productUrl = env.EMAIL_PRODUCT_URL ?? '';

  // Ask the council. ID token only: the user has no vault left to sign with, and
  // nothing reached this way opens anything without someone meeting them. The
  // email to the user is load-bearing (a stolen login must not ask silently), so
  // a failed send withdraws the request and fails the call.
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

      const user = await emergencyRecipient(userId);
      if (!user) return reply.status(404).send({ code: API_ERROR_COUNCIL_NO_ESCROW });

      const config = configuredCouncil(configuredCouncils(), escrow.councilId);
      const ttlDays = config?.requestTtlDays ?? COUNCIL_DEFAULT_REQUEST_TTL_DAYS;
      const now = Date.now();

      let created;
      try {
        // The partial unique index keeps one live request per user against a
        // concurrent POST; the count keeps the daily limit.
        created = await serializable(async (tx) => {
          const recent = await tx.councilRequest.count({ where: { userId, createdAt: { gt: new Date(now - REQUEST_RATE_LIMIT_WINDOW_MS) } } });
          if (recent >= REQUEST_RATE_LIMIT_MAX) return null;

          return tx.councilRequest.create({
            data: {
              userId,
              escrowId: escrow.id,
              ephemeralPublicKey: Buffer.from(base64ToUint8(request.body.ephemeral_public_key)),
              status: 'open',
              expiresAt: new Date(now + ttlDays * DAY_MS),
              releaseNotBefore: new Date(now + (config?.cooldownMinutes ?? 0) * 60_000),
            },
          });
        });
      } catch (err) {
        if (isRetryableRegistrationError(err)) return reply.status(409).send({ code: API_ERROR_COUNCIL_REQUEST_EXISTS });
        throw err;
      }
      if (!created) return reply.status(429).send({ code: API_ERROR_RATE_LIMIT_COUNCIL });

      const label = councilLabel(escrow.councilId);
      try {
        await sendCouncilRecoveryRequested({ recipient: user.email, locale: user.locale, council: label, productUrl });
      } catch (err) {
        await prisma.councilRequest.delete({ where: { id: created.id } });
        throw err;
      }

      for (const { member } of await liveSlots(escrow)) {
        const custodian = await emergencyRecipient(member.userId);
        if (custodian)
          sendCouncilRecoveryToApprove({
            recipient: custodian.email,
            locale: custodian.locale,
            requester: user.labelWithEmail,
            council: label,
            productUrl,
          }).catch(logEmailFailure(app, 'to approve'));
      }

      return { id: created.id, expires_at_millis: created.expiresAt.getTime() };
    }
  );

  // The user's own view: "in progress", then "go and see one of these people".
  // No count and no names before that point. The request key's code lets the
  // browser tell whether the request is its own.
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
                ephemeral_fingerprint: z.string().nullable(),
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

      const settled = await settleRequest(open.id, Date.now());
      if (!settled || settled.stage === 'expired' || settled.stage === 'aborted') return { request: null };

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
          ephemeral_fingerprint: await requestFingerprint(new Uint8Array(open.ephemeralPublicKey)).catch(() => null),
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

      await closeRequest(row.id);

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
        where: { requestId: row.id, slot: { in: settled.facts.contributions.map((c) => c.slot) } },
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
        lang: escrow.credential.lang as MnemonicLanguage,
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
}
