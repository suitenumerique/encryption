import type { FastifyInstance, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { createRemoteJWKSet, jwtVerify } from 'jose';

import { env } from '@encryption/src/server/env';

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
      (error as NodeJS.ErrnoException).code = 'UNAUTHORIZED';
      throw Object.assign(error, { statusCode: 401 });
    }

    const token = authHeader.slice(7);

    try {
      const { payload } = await jwtVerify(token, getJWKS());

      if (payload.azp !== env.OIDC_SERVER_CLIENT_ID) {
        const error = new Error('Token was not issued for this service');
        (error as NodeJS.ErrnoException).code = 'FORBIDDEN';
        throw Object.assign(error, { statusCode: 403 });
      }

      request.userId = payload.sub;
    } catch {
      const error = new Error('Invalid or expired token');
      (error as NodeJS.ErrnoException).code = 'UNAUTHORIZED';
      throw Object.assign(error, { statusCode: 401 });
    }
  });
});
