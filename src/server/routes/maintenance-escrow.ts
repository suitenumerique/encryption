import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { prisma } from '@encryption/src/prisma/client';
import { env } from '@encryption/src/server/env';
import { maintenanceEscrowKeyFingerprint, maintenanceEscrowKeyForEmail } from '@encryption/src/server/maintenance-escrow';
import { GetPublicKeysQuerySchema } from '@encryption/src/server/routes/public-keys';
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

  app.withTypeProvider<ZodTypeProvider>().get('/api/maintenance-escrow/assignments', {
    schema: {
      querystring: GetPublicKeysQuerySchema,
      response: {
        200: z.object({
          assignments: z.array(
            z.object({
              user_id: z.string().uuid(),
              sub: z.string().min(1).optional(), // echoed for records matched through `subs=`, like the directory
              key_fingerprint: z.string().nullable(), // null: no configured key covers this user's email
            })
          ),
        }),
      },
    },
    handler: async (request) => {
      const { subs, user_ids: userIds } = request.query;
      const subsByUser = new Map<string, string[]>();

      if (subs !== undefined) {
        // The active issuer only, as the directory resolves subs (see there).
        const accounts = await prisma.oidcAccount.findMany({ where: { issuer: env.OIDC_ISSUER, subject: { in: subs } } });

        for (const account of accounts) {
          subsByUser.set(account.userId, [...(subsByUser.get(account.userId) ?? []), account.subject]);
        }
      }

      const users = await prisma.user.findMany({
        where: { id: { in: subs !== undefined ? [...subsByUser.keys()] : (userIds ?? []) } },
        select: { id: true, email: true },
        orderBy: { id: 'asc' },
      });
      const entries = env.MAINTENANCE_ESCROW_KEYS ?? [];

      const assignments = await Promise.all(
        users.map(async (user) => {
          const publicKey = maintenanceEscrowKeyForEmail(entries, user.email);
          const base = { user_id: user.id, key_fingerprint: publicKey ? await maintenanceEscrowKeyFingerprint(publicKey) : null };
          const matched = subsByUser.get(user.id);

          return matched ? matched.map((sub) => ({ ...base, sub })) : [base];
        })
      );

      return { assignments: assignments.flat() };
    },
  });
}
