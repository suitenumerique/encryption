import type { FastifyInstance } from 'fastify';

import { prisma } from '@encryption/src/prisma/client';

/**
 * "Who am I" for the interface iframe: maps the caller's OIDC session to the
 * internal user id (minting the User row on first contact, via verifyJWT).
 * Already-registered users are resolved through the public registry instead;
 * this endpoint only matters before a user has any directory row.
 */
export async function meRoute(app: FastifyInstance): Promise<void> {
  app.get('/api/me', {
    preHandler: async (request) => {
      await app.verifyJWT(request);
    },
    handler: async (request) => {
      const userId = request.userId!;
      const user = await prisma.user.findUnique({ where: { id: userId } });

      return { user_id: userId, email: user?.email ?? null };
    },
  });
}
