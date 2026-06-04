import type { FastifyInstance } from 'fastify';
import { randomInt } from 'node:crypto';

import { prisma } from '@encryption/src/prisma/client';
import {
  API_ERROR_MISSING_FIELD,
  API_ERROR_RATE_LIMIT_TRANSFERS,
  API_ERROR_TRANSFER_CODE_ALREADY_USED,
  API_ERROR_TRANSFER_CODE_EXPIRED,
  API_ERROR_TRANSFER_CODE_INVALID,
  API_ERROR_TRANSFER_CODE_WRONG_USER,
} from '@encryption/src/shared/error-codes';

const SESSION_TTL_MS = 60 * 60 * 1000;
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;
const RATE_LIMIT_MAX_SESSIONS = 10;

function generateTransferCode(): string {
  return randomInt(100000, 1000000).toString();
}

export async function deviceTransferRoute(app: FastifyInstance): Promise<void> {
  const cleanupInterval = setInterval(
    async () => {
      try {
        const { count } = await prisma.deviceTransferSession.deleteMany({
          where: { expiresAt: { lt: new Date() } },
        });

        if (count > 0) {
          app.log.info(`Cleaned up ${count} expired device transfer session(s)`);
        }
      } catch (error) {
        app.log.error(error, 'Failed to clean up expired device transfer sessions');
      }
    },
    5 * 60 * 1000
  );

  app.addHook('onClose', () => {
    clearInterval(cleanupInterval);
  });

  app.post('/api/device-transfer/initiate', {
    preHandler: async (request) => {
      await app.verifyJWT(request);
    },
    handler: async (request, reply) => {
      const userId = request.userId!;
      const body = request.body as { encryptedPayload: string };

      if (!body.encryptedPayload || typeof body.encryptedPayload !== 'string') {
        return reply.status(400).send({ code: API_ERROR_MISSING_FIELD, field: 'encryptedPayload' });
      }

      const windowStart = new Date(Date.now() - RATE_LIMIT_WINDOW_MS);

      const recentSessions = await prisma.deviceTransferSession.count({
        where: { userId, createdAt: { gte: windowStart } },
      });

      if (recentSessions >= RATE_LIMIT_MAX_SESSIONS) {
        return reply.status(429).send({
          code: API_ERROR_RATE_LIMIT_TRANSFERS,
          params: { max: RATE_LIMIT_MAX_SESSIONS },
        });
      }

      let code: string;
      let exists: boolean;

      do {
        code = generateTransferCode();
        exists = !!(await prisma.deviceTransferSession.findUnique({ where: { code } }));
      } while (exists);

      const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

      const session = await prisma.deviceTransferSession.create({
        data: { userId, code, encryptedPayload: body.encryptedPayload, expiresAt },
      });

      return { code: session.code, expiresAt: session.expiresAt.toISOString() };
    },
  });

  app.post('/api/device-transfer/claim', {
    preHandler: async (request) => {
      await app.verifyJWT(request);
    },
    handler: async (request, reply) => {
      const userId = request.userId!;
      const body = request.body as { code: string };

      if (!body.code) {
        return reply.status(400).send({ code: API_ERROR_MISSING_FIELD, field: 'code' });
      }

      const session = await prisma.deviceTransferSession.findUnique({ where: { code: body.code } });

      if (!session) {
        return reply.status(404).send({ code: API_ERROR_TRANSFER_CODE_INVALID });
      }

      if (session.expiresAt < new Date()) {
        await prisma.deviceTransferSession.delete({ where: { id: session.id } });

        return reply.status(410).send({ code: API_ERROR_TRANSFER_CODE_EXPIRED });
      }

      if (session.userId !== userId) {
        return reply.status(403).send({ code: API_ERROR_TRANSFER_CODE_WRONG_USER });
      }

      // Delete the session immediately — the poll endpoint will detect the absence as "claimed"
      await prisma.deviceTransferSession.delete({ where: { id: session.id } });

      return { encryptedPayload: session.encryptedPayload };
    },
  });

  app.get('/api/device-transfer/poll/:code', {
    preHandler: async (request) => {
      await app.verifyJWT(request);
    },
    handler: async (request, reply) => {
      const userId = request.userId!;
      const { code } = request.params as { code: string };

      const session = await prisma.deviceTransferSession.findUnique({ where: { code } });

      // Session not found = it was claimed and deleted
      if (!session) {
        return { status: 'claimed' };
      }

      // Security: only the session owner can poll
      if (session.userId !== userId) {
        return reply.status(404).send({ code: API_ERROR_TRANSFER_CODE_INVALID });
      }

      if (session.expiresAt < new Date()) {
        await prisma.deviceTransferSession.delete({ where: { id: session.id } });

        return { status: 'expired' };
      }

      return { status: 'pending', expiresAt: session.expiresAt.toISOString() };
    },
  });
}
