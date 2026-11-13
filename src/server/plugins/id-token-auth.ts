import type { FastifyInstance, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import { prisma } from '@encryption/src/prisma/client';
import { type IdTokenClaims, IdTokenError, verifyIdToken } from '@encryption/src/server/auth/oidc-provider';
import { env } from '@encryption/src/server/env';
import { API_ERROR_FORBIDDEN, API_ERROR_UNAUTHORIZED } from '@encryption/src/shared/error-codes';

declare module 'fastify' {
  interface FastifyRequest {
    /**
     * The INTERNAL user id (users.id), never the OIDC sub. Set by
     * verifyIdToken from the ID token the request presented.
     */
    userId?: string;
    /** The verified claims of that ID token, read by the step-up checks (src/server/auth/step-up.ts). */
    idTokenClaims?: IdTokenClaims;
  }
  interface FastifyInstance {
    verifyIdToken: (request: FastifyRequest) => Promise<void>;
  }
}

function rejection(statusCode: 401 | 403, code: string, message: string): Error {
  const error = new Error(message);
  (error as NodeJS.ErrnoException).code = code;

  return Object.assign(error, { statusCode });
}

/**
 * Authenticate a request by the provider's ID TOKEN it presents as Bearer (the
 * interface got it from POST /api/auth/token). Verified locally against the
 * provider's keys (cached), so no call to the provider per request: signature,
 * issuer, `aud` = our client (an ID token issued to another product is
 * refused), expiry. Then one lookup maps (issuer, sub) to the internal user,
 * minted at login: a token whose user never signed in through our login is
 * refused like an expired one, and the interface signs in again.
 */
// Wrapped with fastify-plugin to break encapsulation — the decorator
// must be visible to route plugins registered on the same app instance.
export const idTokenAuthPlugin = fp(async (app: FastifyInstance): Promise<void> => {
  app.decorate('verifyIdToken', async (request: FastifyRequest) => {
    const header = request.headers.authorization;
    const idToken = header?.startsWith('Bearer ') ? header.slice(7) : null;

    if (!idToken) throw rejection(401, API_ERROR_UNAUTHORIZED, 'Missing or invalid Authorization header');

    let claims: IdTokenClaims;

    try {
      claims = await verifyIdToken(idToken);
    } catch (err) {
      if (err instanceof IdTokenError) throw rejection(401, API_ERROR_UNAUTHORIZED, 'Invalid or expired ID token');
      throw err;
    }

    const account = await prisma.oidcAccount.findUnique({
      where: { issuer_subject: { issuer: env.OIDC_ISSUER, subject: claims.sub } },
      select: { userId: true, disabledAt: true },
    });

    if (!account) throw rejection(401, API_ERROR_UNAUTHORIZED, 'No user signed in with this credential yet');
    if (account.disabledAt) throw rejection(403, API_ERROR_FORBIDDEN, 'Credential belongs to a retired identity provider');

    request.userId = account.userId;
    request.idTokenClaims = claims;
  });
});
