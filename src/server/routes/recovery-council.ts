import type { FastifyInstance } from 'fastify';

import { escrowRoutes } from '@encryption/src/server/routes/recovery-council/escrow';
import { custodianRequestRoutes } from '@encryption/src/server/routes/recovery-council/requests-custodian';
import { userRequestRoutes } from '@encryption/src/server/routes/recovery-council/requests-user';
import { reshareRoutes } from '@encryption/src/server/routes/recovery-council/reshare';
import { rosterRoutes } from '@encryption/src/server/routes/recovery-council/roster';
import { registerTransportAuth } from '@encryption/src/server/routes/transport-auth';
import { configureZodValidation } from '@encryption/src/server/zod-validation';

/** The recovery council API (architecture.md Appendix F): rosters, escrows, recovery requests, resharing. */
export async function recoveryCouncilRoute(app: FastifyInstance): Promise<void> {
  configureZodValidation(app);
  registerTransportAuth(app);

  rosterRoutes(app);
  escrowRoutes(app);
  userRequestRoutes(app);
  custodianRequestRoutes(app);
  reshareRoutes(app);
}
