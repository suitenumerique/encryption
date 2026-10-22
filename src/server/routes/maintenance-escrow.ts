import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { prisma } from '@encryption/src/prisma/client';
import { env } from '@encryption/src/server/env';
import { maintenanceEscrowKeyFingerprint, maintenanceEscrowKeyForEmail } from '@encryption/src/server/maintenance-escrow';
import { configureZodValidation } from '@encryption/src/server/zod-validation';

/**
 * Which maintenance key escrows the resources each user owns, by the fingerprint
 * of one of the keys the vault received in its runtime config. The vault asks it
 * for a resource's owner before wrapping its copy: the email deciding it is the
 * one the server keeps from the identity provider, never one a product declares.
 *
 * Unauthenticated like the public-key directory, for the same reason: the vault
 * calls it during a product's share, which carries no token. It reveals which
 * group of email domains a user belongs to, nothing else.
 */
export async function maintenanceEscrowRoute(app: FastifyInstance): Promise<void> {
  configureZodValidation(app);

  // One owner per request: a resource has exactly one, which is all the vault asks
  // about. The vault names its own user by internal id, a product's owner by sub.
  app.withTypeProvider<ZodTypeProvider>().get('/api/maintenance-escrow/assignment', {
    schema: {
      querystring: z
        .object({ user_id: z.string().uuid().optional(), sub: z.string().min(1).max(200).optional() })
        .refine((query) => (query.user_id === undefined) !== (query.sub === undefined), { message: 'exactly one of user_id or sub is required' }),
      response: {
        // null: no copy, because no configured key covers the user's email, or the
        // service has no account for them (so no email to go by).
        200: z.object({ key_fingerprint: z.string().nullable() }),
      },
    },
    handler: async (request) => {
      const { user_id: userId, sub } = request.query;
      // A sub resolves under the active issuer only, as in the directory (see there).
      const user = await prisma.user.findFirst({
        where: sub !== undefined ? { oidcAccounts: { some: { issuer: env.OIDC_ISSUER, subject: sub } } } : { id: userId },
        select: { email: true },
      });
      const publicKey = user ? maintenanceEscrowKeyForEmail(env.MAINTENANCE_ESCROW_KEYS ?? [], user.email) : null;

      return { key_fingerprint: publicKey ? await maintenanceEscrowKeyFingerprint(publicKey) : null };
    },
  });
}
