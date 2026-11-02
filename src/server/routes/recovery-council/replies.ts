import type { FastifyInstance, FastifyReply } from 'fastify';

import { API_ERROR_COUNCIL_SIGNATURE_INVALID } from '@encryption/src/shared/error-codes';

export function sendSignatureError(reply: FastifyReply) {
  return reply.status(400).send({ code: API_ERROR_COUNCIL_SIGNATURE_INVALID });
}

/** Notification emails are best effort once the state they announce is stored. */
export function logEmailFailure(app: FastifyInstance, context: string) {
  return (err: unknown) => app.log.error({ err }, `recovery council email failed: ${context}`);
}
