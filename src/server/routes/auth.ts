import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { type IdentityClaims, isIncomplete, pickIdentity } from '@encryption/src/server/auth/identity-claims';
import { resolveOidcAccount } from '@encryption/src/server/auth/oidc-accounts';
import {
  type IdTokenClaims,
  IdTokenError,
  OidcLoginError,
  buildAuthorizationUrl,
  exchangeCode,
  fetchUserinfo,
  verifyIdToken,
} from '@encryption/src/server/auth/oidc-provider';
import { hasSecondFactor } from '@encryption/src/server/auth/step-up';
import { env } from '@encryption/src/server/env';
import { errorResponses } from '@encryption/src/server/error-response';
import { configureZodValidation } from '@encryption/src/server/zod-validation';
import { API_ERROR_NAME_CLAIMS_REQUIRED, API_ERROR_OIDC_LOGIN_FAILED, API_ERROR_WRONG_USER } from '@encryption/src/shared/error-codes';

// What the login tab generates and keeps until the provider sends it back:
// random base64url strings (RFC 7636 §4.1 sizes the PKCE verifier at 43-128
// characters, its S256 challenge is exactly 43).
const randomParameter = z.string().regex(/^[A-Za-z0-9_-]{22,128}$/);
const pkceVerifier = z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/);
const pkceChallenge = z.string().regex(/^[A-Za-z0-9_-]{43}$/);

/**
 * The interface's login, run by the server as a confidential client:
 *
 *  1. GET  /api/auth/authorize: the login tab is sent here with the state,
 *     nonce and PKCE challenge it generated, and redirected to the provider.
 *  2. The provider redirects back to /auth/callback, a page of the interface,
 *     which checks the state and posts the code here:
 *  3. POST /api/auth/token: the code is exchanged (client secret + PKCE
 *     verifier), the ID token verified against the nonce, userinfo asked for
 *     the email and names the ID token lacks, the user resolved (minted on first contact), and the
 *     ID TOKEN handed back. The interface presents it as the Bearer credential
 *     of every call until it expires; the access token is dropped here.
 */
export async function authRoute(app: FastifyInstance): Promise<void> {
  configureZodValidation(app);

  // A navigation, not an API call (the browser follows the redirect), hence
  // hidden from the OpenAPI document and the generated client.
  app.withTypeProvider<ZodTypeProvider>().get('/api/auth/authorize', {
    schema: {
      hide: true,
      querystring: z.object({
        state: randomParameter,
        nonce: randomParameter,
        code_challenge: pkceChallenge,
        prompt: z.literal('login').optional(),
        // A step-up (RFC 9470), after an action answered `insufficient_user_authentication`.
        step_up: z.literal('1').optional(),
      }),
    },
    handler: async (request, reply) => {
      const { state, nonce, code_challenge, prompt, step_up } = request.query;
      const location = await buildAuthorizationUrl({ state, nonce, codeChallenge: code_challenge, prompt, stepUp: step_up === '1' });

      return reply.redirect(location, 302);
    },
  });

  app.withTypeProvider<ZodTypeProvider>().post('/api/auth/token', {
    schema: {
      body: z.object({
        code: z.string().min(1).max(4096),
        code_verifier: pkceVerifier,
        nonce: randomParameter,
        // The OIDC sub the product says is signed in. When given, a login as
        // anyone else is refused BEFORE any user is resolved or minted, so
        // picking the wrong account at the provider leaves no trace here.
        expected_sub: z.string().min(1).optional(),
      }),
      response: {
        200: z.object({
          /** The provider's ID token: the Bearer credential for every other call. */
          id_token: z.string(),
          /** Its `exp`, the moment the interface has to sign in again. */
          expires_at: z.iso.datetime(),
          sub: z.string(),
          user_id: z.string().uuid(),
          email: z.string().nullable(),
          first_name: z.string(),
          last_name: z.string(),
          /** Whether the provider reported a second factor for this login (see step-up.ts). */
          second_factor: z.boolean(),
        }),
        ...errorResponses(401, 403, 409),
      },
    },
    handler: async (request, reply) => {
      const { code, code_verifier, nonce, expected_sub } = request.body;

      let idToken: string;
      let idClaims: IdTokenClaims;
      let identity: IdentityClaims;

      try {
        const tokens = await exchangeCode(code, code_verifier);

        idToken = tokens.idToken;
        idClaims = await verifyIdToken(tokens.idToken, { nonce });

        if (expected_sub !== undefined && idClaims.sub !== expected_sub) {
          return reply.status(409).send({ code: API_ERROR_WRONG_USER });
        }

        // The ID token first: a provider may carry everything there. Userinfo,
        // where the `claims` parameter asked for the email and names, fills in
        // whatever it lacks; the ID token keeps precedence on what it has.
        identity = pickIdentity([idClaims]);

        if (isIncomplete(identity)) {
          identity = pickIdentity([idClaims, await fetchUserinfo(tokens.accessToken, idClaims.sub)]);
        }
      } catch (err) {
        if (!(err instanceof OidcLoginError) && !(err instanceof IdTokenError)) throw err;

        // The reason is logged (it names a failure, never a credential); the
        // client only learns that the login did not go through.
        request.log.warn({ reason: err.message }, 'OIDC login rejected');

        return reply.status(401).send({ code: API_ERROR_OIDC_LOGIN_FAILED });
      }

      // Checked before the account is resolved, so a provider sending no names
      // mints nobody. The email has its own rule (required at first contact
      // only), applied by resolveOidcAccount.
      if (identity.firstName === null || identity.lastName === null) {
        request.log.warn({ firstName: identity.firstName !== null, lastName: identity.lastName !== null }, 'OIDC login without the required names');

        return reply.status(403).send({ code: API_ERROR_NAME_CLAIMS_REQUIRED });
      }

      const account = await resolveOidcAccount(env.OIDC_ISSUER, idClaims.sub, {
        email: identity.email,
        email_verified: identity.emailVerified,
        locale: identity.locale,
      });

      if (account.linkedByEmail) {
        // The one mutation of the trust-critical mapping table that happens
        // without operator intent or cryptographic proof: leave a trace.
        request.log.info({ userId: account.userId }, 'linked new OIDC credential to existing user via verified-email fallback');
      }

      return {
        id_token: idToken,
        expires_at: new Date(idClaims.exp * 1000).toISOString(),
        sub: idClaims.sub,
        user_id: account.userId,
        email: identity.email,
        first_name: identity.firstName,
        last_name: identity.lastName,
        second_factor: hasSecondFactor(idClaims),
      };
    },
  });
}
