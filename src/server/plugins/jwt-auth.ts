import type { FastifyInstance, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { createRemoteJWKSet, jwtVerify } from 'jose';

import { env } from '@encryption/src/server/env';
import { API_ERROR_FORBIDDEN, API_ERROR_UNAUTHORIZED } from '@encryption/src/shared/error-codes';

declare module 'fastify' {
  interface FastifyRequest {
    userId?: string;
  }
  interface FastifyInstance {
    verifyJWT: (request: FastifyRequest) => Promise<void>;
  }
}

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJWKS(): ReturnType<typeof createRemoteJWKSet> {
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(env.OIDC_JWKS_URL));
  }

  return jwks;
}

// Wrapped with fastify-plugin to break encapsulation — the decorator
// must be visible to route plugins registered on the same app instance.
export const jwtAuthPlugin = fp(async (app: FastifyInstance): Promise<void> => {
  app.decorate('verifyJWT', async (request: FastifyRequest) => {
    const authHeader = request.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
      const error = new Error('Missing or invalid Authorization header');
      (error as NodeJS.ErrnoException).code = API_ERROR_UNAUTHORIZED;
      throw Object.assign(error, { statusCode: 401 });
    }

    const token = authHeader.slice(7);

    // Only signature/expiry/issuer verification lives in the try: those failures
    // are genuinely "invalid token" (401). Binding the expected issuer here means
    // a token from another OIDC provider is rejected by jose itself.
    let payload: Awaited<ReturnType<typeof jwtVerify>>['payload'];

    try {
      ({ payload } = await jwtVerify(token, getJWKS(), { issuer: env.OIDC_ISSUER }));
    } catch {
      const error = new Error('Invalid or expired token');
      (error as NodeJS.ErrnoException).code = API_ERROR_UNAUTHORIZED;
      throw Object.assign(error, { statusCode: 401 });
    }

    // Authorization checks run OUTSIDE the try, so they surface their own status
    // instead of being swallowed and remapped to 401 by the catch above.

    // A valid token that was not issued for this service is a 403, not a 401.
    if (payload.azp !== env.OIDC_SERVER_CLIENT_ID) {
      const error = new Error('Token was not issued for this service');
      (error as NodeJS.ErrnoException).code = API_ERROR_FORBIDDEN;
      throw Object.assign(error, { statusCode: 403 });
    }

    // A token with no `sub` would leave userId undefined; Prisma then DROPS the
    // undefined filter and can return an arbitrary user's rows. Reject it.
    if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
      const error = new Error('Token has no subject');
      (error as NodeJS.ErrnoException).code = API_ERROR_UNAUTHORIZED;
      throw Object.assign(error, { statusCode: 401 });
    }

    request.userId = payload.sub;
  });
});
