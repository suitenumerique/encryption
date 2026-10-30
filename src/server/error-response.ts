import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { apiErrorMessage } from '@encryption/src/server/i18n';

/**
 * The one error shape every route returns: a stable `code` from
 * src/shared/error-codes.ts, which the frontend translates. `params` carries
 * interpolation values for the few codes that need them, and `message` is a
 * developer-facing English default for consumers that are NOT a translated UI
 * (logs, the client SDK, product backends). The code stays authoritative: no UI
 * should branch on the message.
 *
 * Declaring these alongside the 200 response is what puts the error shape into
 * the OpenAPI document, so the generated client types `error` instead of
 * leaving failure handling untyped.
 */
export const ApiErrorResponseSchema = z.object({
  code: z.string(),
  params: z.record(z.string(), z.unknown()).optional(),
  message: z.string().optional(),
});

/**
 * The failure statuses the registration helpers compute and hand back to a
 * route to forward. Typed as a precise union rather than `number` so a route
 * forwarding one still satisfies the statuses declared in its own schema; a new
 * status added in registration-core will not compile until the routes that
 * forward it declare it too.
 */
export type RegistrationErrorStatus = 400 | 404 | 409 | 410 | 429;

/**
 * Declare the failure statuses a route can answer with, e.g.
 * `response: { 200: Body, ...errorResponses(404, 429) }`.
 *
 * Without this the Zod type provider narrows `reply.status()` to 200 alone and
 * every error path stops compiling, which is the intended pressure: a route's
 * failure modes belong in its schema.
 */
export function errorResponses<T extends number>(...statuses: T[]): Record<T, typeof ApiErrorResponseSchema> {
  return Object.fromEntries(statuses.map((status) => [status, ApiErrorResponseSchema])) as Record<T, typeof ApiErrorResponseSchema>;
}

/**
 * Add the English `message` to every error payload, once, for the whole server.
 * The text comes from the shared i18n files (errors.api.{code}), so there is a
 * single source for both the interface's translation and this default.
 *
 * `preSerialization` (not `onSend`) so the payload is still an object: it runs
 * before the Zod serializer, which means `message` is part of the declared
 * schema and survives serialization instead of being stripped as an unknown key.
 *
 * Doing it here rather than at each `reply.send({ code })` keeps the ~30 error
 * sites unchanged and makes it impossible for one of them to forget.
 */
export function attachApiErrorMessages(app: FastifyInstance): void {
  app.addHook('preSerialization', async (_request, reply, payload) => {
    if (reply.statusCode < 400 || typeof payload !== 'object' || payload === null) {
      return payload;
    }

    const body = payload as { code?: unknown; params?: Record<string, unknown>; message?: unknown };

    if (typeof body.code !== 'string' || body.message !== undefined) {
      return payload;
    }

    const message = apiErrorMessage(body.code, body.params);

    return message ? { ...body, message } : payload;
  });
}
