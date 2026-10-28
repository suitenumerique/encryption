import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { type ReshareKeyBindingRecord, verifyReshareCommitments, verifyReshareKeyBinding } from '@encryption/src/crypto/council';
import { ensureSodium } from '@encryption/src/crypto/encryption';
import { base64ToUint8 } from '@encryption/src/crypto/encryption-backup';
import { checkHelperCommitments, decodeCommitments } from '@encryption/src/crypto/shamir';
import { prisma } from '@encryption/src/prisma/client';
import { requireStepUp } from '@encryption/src/server/auth/step-up';
import { councilChain, custodianOf, escrowRecordWire, rosterVersionWire, serializable, sha256 } from '@encryption/src/server/council-core';
import {
  cancelReshareSession,
  capsuleWire,
  moveCompleteEscrows,
  moveEscrowIfComplete,
  reshareProgress,
} from '@encryption/src/server/council-reshare-core';
import { errorResponses } from '@encryption/src/server/error-response';
import { sendSignatureError } from '@encryption/src/server/routes/recovery-council/replies';
import { isRetryableRegistrationError } from '@encryption/src/server/routes/registration-core';
import { SKIP_SIG, assertUserId } from '@encryption/src/server/routes/transport-auth';
import {
  API_ERROR_COUNCIL_NOT_CUSTODIAN,
  API_ERROR_COUNCIL_NOT_FOUND,
  API_ERROR_COUNCIL_RESHARE_INVALID,
  API_ERROR_COUNCIL_RESHARE_KEYS_SENT,
} from '@encryption/src/shared/error-codes';
import {
  CouncilCheckBatchSchema,
  CouncilCheckResultsBodySchema,
  CouncilReshareBatchSchema,
  CouncilReshareKeysBodySchema,
  CouncilReshareSubSharesBodySchema,
} from '@encryption/src/shared/schemas/recovery-council';

const RESHARE_BATCH_SIZE = 100;

async function helperOf(sessionId: string, userId: string) {
  const session = await prisma.councilReshareSession.findUnique({ where: { id: sessionId } });
  if (!session || session.status !== 'open') return null;

  const custodian = await custodianOf(session.councilId, userId);
  if (!custodian || !session.helperSlots.includes(custodian.member.slot) || custodian.head.id !== session.targetRosterVersionId) return null;

  return { session, ...custodian };
}

function uncheckedCapsulesOf(councilId: string, member: { slot: number; identityId: string }) {
  return { escrow: { councilId }, slot: member.slot, identityId: member.identityId, sessionId: { not: null }, checkedAt: null };
}

export function reshareRoutes(app: FastifyInstance): void {
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

      // One open session per council, and only towards the current head.
      const session = await serializable(async (tx) => {
        if ((await custodianOf(councilId, request.userId, tx))?.head.id !== custodian.head.id) return null;
        if (await tx.councilReshareSession.findFirst({ where: { councilId, status: 'open' } })) return null;

        return tx.councilReshareSession.create({
          data: {
            councilId,
            sourceRosterVersionId: source.id,
            targetRosterVersionId: custodian.head.id,
            helperSlots: helpers,
            status: 'open',
            createdByUserId: request.userId,
          },
        });
      });
      if (!session) return reply.status(409).send({ code: API_ERROR_COUNCIL_RESHARE_INVALID });

      return { session_id: session.id };
    }
  );

  // A helper's next batch: the escrows they have not processed yet, with their own
  // capsule of each, and the signed chain their vault verifies the target against.
  // Escrows every helper already sealed but that did not move yet (a lost race, a
  // recovery that has since ended) move first.
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
      await moveCompleteEscrows(session.id);

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
  // new custodian only ever adds up sub-shares from a real helper. Sent once per
  // helper and session: capsules already moved open with them, so they are never
  // replaced (the vault derives the same keys again after a reload).
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/councils/reshare/:sessionId/keys',
    {
      schema: {
        params: z.object({ sessionId: z.string().uuid() }),
        body: CouncilReshareKeysBodySchema,
        response: { 200: z.object({ stored: z.number().int() }), ...errorResponses(400, 401, 403, 409) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      if (!requireStepUp(request, reply)) return reply;

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

      try {
        const stored = await prisma.$transaction(async (tx) => {
          if ((await tx.councilReshareKey.count({ where: { sessionId: session.id, helperSlot: member.slot } })) > 0) return false;

          await tx.councilReshareKey.createMany({
            data: request.body.keys.map((k) => ({
              sessionId: session.id,
              helperSlot: member.slot,
              recipientSlot: k.recipient_slot,
              wrappedTransferKey: k.wrapped_transfer_key,
              signature: Buffer.from(base64ToUint8(k.binding_signature)),
            })),
          });

          return true;
        });
        if (!stored) return reply.status(409).send({ code: API_ERROR_COUNCIL_RESHARE_KEYS_SENT });
      } catch (err) {
        // A concurrent POST of the same helper: the unique index lets one through.
        if (isRetryableRegistrationError(err)) return reply.status(409).send({ code: API_ERROR_COUNCIL_RESHARE_KEYS_SENT });
        throw err;
      }

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
        response: { 200: z.object({ moved: z.number().int(), remaining: z.number().int() }), ...errorResponses(400, 401, 403) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      if (!requireStepUp(request, reply)) return reply;

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

      // A resend replaces this helper's rows for those escrows, only while they are
      // still on the source: once moved, their capsules open with what is stored.
      const stored = await serializable(async (tx) => {
        const current = await tx.councilEscrow.count({ where: { id: { in: escrowIds }, rosterVersionId: session.sourceRosterVersionId } });
        const open = await tx.councilReshareSession.count({ where: { id: session.id, status: 'open' } });
        if (current !== escrowIds.length || open === 0) return false;

        await tx.councilSubShare.deleteMany({ where: { sessionId: session.id, helperSlot: member.slot, escrowId: { in: escrowIds } } });
        await tx.councilReshareCommitment.deleteMany({ where: { sessionId: session.id, helperSlot: member.slot, escrowId: { in: escrowIds } } });
        await tx.councilReshareCommitment.createMany({
          data: request.body.escrows.map((entry) => ({
            sessionId: session.id,
            escrowId: entry.escrow_id,
            helperSlot: member.slot,
            commitments: Buffer.from(base64ToUint8(entry.commitments)),
            signature: Buffer.from(base64ToUint8(entry.commitments_signature)),
          })),
        });
        await tx.councilSubShare.createMany({
          data: request.body.escrows.flatMap((entry) =>
            entry.sub_shares.map((s) => ({
              sessionId: session.id,
              escrowId: entry.escrow_id,
              helperSlot: member.slot,
              recipientSlot: s.recipient_slot,
              sealed: s.sealed,
            }))
          ),
        });

        return true;
      });
      if (!stored) return reply.status(400).send({ code: API_ERROR_COUNCIL_RESHARE_INVALID });

      let moved = 0;
      for (const escrowId of escrowIds) {
        if (await moveEscrowIfComplete(session.id, escrowId)) moved++;
      }
      // Escrows of earlier batches whose move was held back or lost a race.
      moved += await moveCompleteEscrows(session.id);

      return { moved, remaining: (await reshareProgress(session.id, member.slot)).remaining };
    }
  );

  // Stop a resharing. Escrows it already moved stay moved (their capsules need the
  // session's keys and sub-shares); the others stay on the source version.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/councils/reshare/:sessionId/cancel',
    {
      schema: {
        params: z.object({ sessionId: z.string().uuid() }),
        response: { 200: z.object({ cancelled: z.boolean() }), ...errorResponses(401, 403, 404) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      if (!requireStepUp(request, reply)) return reply;

      const session = await prisma.councilReshareSession.findUnique({ where: { id: request.params.sessionId } });
      if (!session || session.status !== 'open') return reply.status(404).send({ code: API_ERROR_COUNCIL_NOT_FOUND });
      if (!(await custodianOf(session.councilId, request.userId))) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      if (!(await cancelReshareSession(session.id))) return reply.status(404).send({ code: API_ERROR_COUNCIL_NOT_FOUND });

      return { cancelled: true };
    }
  );

  // The next reshared shares this custodian's vault should open and check, with
  // the chain it verifies their helpers against.
  app.withTypeProvider<ZodTypeProvider>().get(
    '/api/councils/:councilId/shares-to-check',
    {
      ...SKIP_SIG,
      schema: {
        params: z.object({ councilId: z.string().min(1).max(64) }),
        response: { 200: CouncilCheckBatchSchema, ...errorResponses(403) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const { councilId } = request.params;
      const custodian = await custodianOf(councilId, request.userId);
      if (!custodian) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const where = uncheckedCapsulesOf(councilId, custodian.member);
      const [capsules, remaining] = await Promise.all([
        prisma.councilCapsule.findMany({
          where,
          include: { escrow: { include: { credential: true, signedRosterVersion: true } } },
          orderBy: { escrowId: 'asc' },
          take: RESHARE_BATCH_SIZE,
        }),
        prisma.councilCapsule.count({ where }),
      ]);

      const escrows = [];
      for (const capsule of capsules) {
        escrows.push({
          escrow_id: capsule.escrowId,
          user_id: capsule.escrow.userId,
          record: escrowRecordWire(capsule.escrow, sha256(new Uint8Array(capsule.escrow.credential.authPublicKey))),
          capsule: await capsuleWire(capsule, capsule.escrowId),
        });
      }

      return { council_id: councilId, chain: (await councilChain(councilId)).map(rosterVersionWire), escrows, remaining };
    }
  );

  // What the vault found. Only this custodian's own unchecked capsules change; a
  // share found invalid stops counting in the escrow's health, so its user is
  // asked to set up again when too few valid shares are left.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/councils/:councilId/shares-checked',
    {
      schema: {
        params: z.object({ councilId: z.string().min(1).max(64) }),
        body: CouncilCheckResultsBodySchema,
        response: { 200: z.object({ checked: z.number().int(), invalid: z.number().int() }), ...errorResponses(401, 403) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      if (!requireStepUp(request, reply)) return reply;

      const { councilId } = request.params;
      const custodian = await custodianOf(councilId, request.userId);
      if (!custodian) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_CUSTODIAN });

      const capsules = await prisma.councilCapsule.findMany({
        where: { ...uncheckedCapsulesOf(councilId, custodian.member), escrowId: { in: request.body.results.map((r) => r.escrow_id) } },
        include: { session: true },
      });
      const now = new Date();

      // Each update only applies to a capsule still unchecked: a report sent twice
      // at once counts once.
      const updates = await prisma.$transaction(
        capsules.map((capsule) => {
          const result = request.body.results.find((r) => r.escrow_id === capsule.escrowId)!;
          const faulty =
            !result.valid && result.faulty_helper_slot !== null && capsule.session?.helperSlots.includes(result.faulty_helper_slot)
              ? result.faulty_helper_slot
              : null;

          return prisma.councilCapsule.updateMany({
            where: { id: capsule.id, checkedAt: null },
            data: { checkedAt: now, invalid: !result.valid, faultyHelperSlot: faulty },
          });
        })
      );

      let checked = 0;
      let invalid = 0;
      updates.forEach((update, i) => {
        if (update.count === 0) return;
        checked++;
        if (!request.body.results.find((r) => r.escrow_id === capsules[i].escrowId)!.valid) invalid++;
      });

      if (invalid > 0)
        request.log.warn({ councilId, custodianSlot: custodian.member.slot, invalid }, 'council reshared shares found invalid by their custodian');

      return { checked, invalid };
    }
  );
}
