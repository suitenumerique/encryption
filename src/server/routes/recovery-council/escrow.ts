import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { prisma } from '@encryption/src/prisma/client';
import { serializable } from '@encryption/src/server/council-core';
import { CouncilHeadChangedError, checkEscrowSubmission, enrollableCouncil, writeEscrow } from '@encryption/src/server/council-escrow';
import { openRequestOf } from '@encryption/src/server/council-requests-core';
import { errorResponses } from '@encryption/src/server/error-response';
import { isRetryableRegistrationError } from '@encryption/src/server/routes/registration-core';
import { assertUserId } from '@encryption/src/server/routes/transport-auth';
import {
  API_ERROR_CONCURRENT_REGISTRATION,
  API_ERROR_COUNCIL_NOT_COVERED,
  API_ERROR_COUNCIL_REQUEST_EXISTS,
  API_ERROR_COUNCIL_ROSTER_CHANGED,
  API_ERROR_VAULT_NOT_FOUND,
} from '@encryption/src/shared/error-codes';
import { CouncilEscrowBodySchema } from '@encryption/src/shared/schemas/recovery-council';

export function escrowRoutes(app: FastifyInstance): void {
  // Enroll (or re-enroll) the caller's current vault with the head of their
  // council. Explicit and identity-signed: the vault built it after the user
  // accepted the council in the interface. A previous escrow of this vault is
  // replaced; one with a recovery in progress is not.
  app.withTypeProvider<ZodTypeProvider>().post(
    '/api/councils/escrow',
    {
      schema: {
        body: CouncilEscrowBodySchema,
        response: { 200: z.object({ id: z.string().uuid() }), ...errorResponses(400, 403, 404, 409) },
      },
    },
    async (request, reply) => {
      assertUserId(request);
      const userId = request.userId;
      const body = request.body;

      const keyring = await prisma.vaultKeyring.findFirst({ where: { userId, disabledAt: null } });
      if (!keyring) return reply.status(404).send({ code: API_ERROR_VAULT_NOT_FOUND });

      // Only the council covering the user, or the one their escrow already names:
      // custodians never receive capsules, requests and emails for strangers.
      if (body.council_id !== (await enrollableCouncil(userId))) return reply.status(403).send({ code: API_ERROR_COUNCIL_NOT_COVERED });

      // Settles an expired request first, so it no longer counts below.
      if (await openRequestOf(userId)) return reply.status(409).send({ code: API_ERROR_COUNCIL_REQUEST_EXISTS });

      const checked = await checkEscrowSubmission(userId, body);
      if (!checked.ok) return reply.status(checked.status).send({ code: checked.code });

      try {
        const created = await serializable(async (tx) => {
          if ((await tx.councilRequest.count({ where: { userId, status: { in: ['open', 'released'] } } })) > 0) return null;

          const previous = await tx.councilEscrow.findMany({
            where: { userId, credential: { vaultId: keyring.id } },
            select: { credentialId: true },
          });
          const id = await writeEscrow(tx, userId, keyring.id, body, checked);
          await tx.vaultCredential.deleteMany({ where: { id: { in: previous.map((p) => p.credentialId) } } });

          return id;
        });
        if (!created) return reply.status(409).send({ code: API_ERROR_COUNCIL_REQUEST_EXISTS });

        return { id: created };
      } catch (err) {
        if (err instanceof CouncilHeadChangedError) return reply.status(409).send({ code: API_ERROR_COUNCIL_ROSTER_CHANGED });
        if (isRetryableRegistrationError(err)) return reply.status(409).send({ code: API_ERROR_CONCURRENT_REGISTRATION });
        throw err;
      }
    }
  );
}
