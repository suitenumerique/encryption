import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { createHash, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';

import { prisma } from '@encryption/src/prisma/client';
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
import {
  API_ERROR_INVALID_REQUEST,
  API_ERROR_NAME_CLAIMS_REQUIRED,
  API_ERROR_OIDC_LOGIN_FAILED,
  API_ERROR_SIGN_IN_EXPIRED,
  API_ERROR_WRONG_USER,
} from '@encryption/src/shared/error-codes';
import { SUPPORTED_LOCALES } from '@encryption/src/shared/locale';

// What the interface iframe generates for a sign-in: random base64url strings
// (RFC 7636 §4.1 sizes the PKCE verifier at 43-128 characters, its S256
// challenge is exactly 43).
const randomParameter = z.string().regex(/^[A-Za-z0-9_-]{22,128}$/);
const pkceVerifier = z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/);
const pkceChallenge = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const authorizationCode = z.string().min(1).max(4096);

// How long a sign-in may stay in flight, from the tab's departure to the
// provider to the iframe's exchange: the user may take their time there.
const RELAY_LIFETIME_MS = 60 * 60 * 1000;

function s256(verifier: string): Buffer {
  return createHash('sha256').update(verifier).digest();
}

/**
 * The interface's sign-in, run by the server as a confidential client and
 * relayed through it (architecture.md §2.1: a provider page sending COOP cuts the
 * link between the sign-in tab and the iframe that opened it, so the result
 * cannot travel back through the browser):
 *
 *  1. GET  /api/auth/authorize: the sign-in tab is sent here with the state,
 *     nonce and PKCE challenge the iframe generated. The state and the
 *     challenge are kept, and the tab is redirected to the provider.
 *  2. The provider redirects back to /auth/callback, a page of the interface,
 *     which checks the state and deposits the code here, with the relay id the
 *     iframe gave it: POST /api/auth/relay.
 *  3. POST /api/auth/token, polled by the iframe with the relay id: `202` until
 *     the code is deposited, then the PKCE verifier is checked against the kept
 *     challenge (whether or not the provider checks it too), the code exchanged
 *     (client secret + verifier), the ID token verified against the nonce,
 *     userinfo asked for the email and names the ID token lacks, the user
 *     resolved (minted on first contact), and the ID TOKEN handed back. The
 *     interface presents it as the Bearer credential of every call until it
 *     expires; the access token is dropped here.
 *
 * The code never travels back to a browser, and no token is ever stored.
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
        // The interface's language, for the provider's sign-in pages.
        ui_locales: z.enum(SUPPORTED_LOCALES).optional(),
      }),
      response: { ...errorResponses(400) },
    },
    handler: async (request, reply) => {
      const { state, nonce, code_challenge, prompt, step_up, ui_locales } = request.query;
      const now = new Date();

      // Sign-ins nobody finished, swept here rather than by a job: this is the only way rows are added.
      await prisma.authRelay.deleteMany({ where: { expiresAt: { lt: now } } });

      try {
        await prisma.authRelay.create({
          data: { state, codeChallenge: code_challenge, expiresAt: new Date(now.getTime() + RELAY_LIFETIME_MS) },
        });
      } catch (err) {
        if ((err as { code?: unknown } | null)?.code !== 'P2002') throw err;

        // The same sign-in passing again (the browser's back button, a reload)
        // goes on to the provider: its code still lands in the one deposit, and
        // only the iframe holding the relay id and the verifier can collect it.
        // Under another challenge it would be a second sign-in sharing that code.
        const existing = await prisma.authRelay.findUnique({ where: { state } });
        const sameSignIn = existing?.codeChallenge === code_challenge && existing.code === null && existing.expiresAt >= now;

        if (!sameSignIn) return reply.status(400).send({ code: API_ERROR_INVALID_REQUEST });
      }

      const location = await buildAuthorizationUrl({
        state,
        nonce,
        codeChallenge: code_challenge,
        prompt,
        stepUp: step_up === '1',
        uiLocale: ui_locales,
      });

      return reply.redirect(location, 302);
    },
  });

  app.withTypeProvider<ZodTypeProvider>().post('/api/auth/relay', {
    schema: {
      body: z.object({
        // The state of the callback address, which the tab checked against the one it was handed.
        state: randomParameter,
        // The handle of this sign-in, which only the iframe and its tab know.
        relay_id: randomParameter,
        code: authorizationCode,
      }),
      response: {
        200: z.object({ status: z.literal('deposited') }),
        ...errorResponses(409),
      },
    },
    handler: async (request, reply) => {
      const { state, relay_id, code } = request.body;

      try {
        // Once per sign-in: a deposit already made, whoever made it, stays.
        const { count } = await prisma.authRelay.updateMany({
          where: { state, code: null, expiresAt: { gte: new Date() } },
          data: { relayId: relay_id, code },
        });

        if (count === 0) return reply.status(409).send({ code: API_ERROR_SIGN_IN_EXPIRED });
      } catch (err) {
        // A relay id already used by another sign-in.
        if ((err as { code?: unknown } | null)?.code === 'P2002') return reply.status(409).send({ code: API_ERROR_SIGN_IN_EXPIRED });

        throw err;
      }

      return { status: 'deposited' as const };
    },
  });

  app.withTypeProvider<ZodTypeProvider>().post('/api/auth/token', {
    schema: {
      body: z.object({
        relay_id: randomParameter,
        code_verifier: pkceVerifier,
        nonce: randomParameter,
        // The OIDC sub the product says is signed in. When given, a login as
        // anyone else is refused BEFORE any user is resolved or minted, so
        // picking the wrong account at the provider leaves no trace here.
        expected_sub: z.string().min(1).optional(),
        // The interface's language (the product's, else the browser's): the
        // account's language when the provider sends no `locale`.
        language: z.enum(SUPPORTED_LOCALES).optional(),
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
        /** Nothing deposited under this relay id yet: the user is still at the provider. Ask again. */
        202: z.object({ status: z.literal('pending') }),
        ...errorResponses(401, 403, 409),
      },
    },
    handler: async (request, reply) => {
      const { relay_id, code_verifier, nonce, expected_sub, language } = request.body;
      const relay = await prisma.authRelay.findUnique({ where: { relayId: relay_id } });

      if (relay === null) return reply.status(202).send({ status: 'pending' as const });

      // Tried once, whatever the outcome: the provider's code is single use anyway.
      // A concurrent exchange of the same deposit finds nothing left to delete.
      const { count } = await prisma.authRelay.deleteMany({ where: { state: relay.state, relayId: relay_id } });

      if (count === 0 || relay.code === null) return reply.status(202).send({ status: 'pending' as const });
      if (relay.expiresAt < new Date()) return reply.status(409).send({ code: API_ERROR_SIGN_IN_EXPIRED });

      // PKCE checked here too, against the challenge kept at authorize: a provider
      // may accept `code_challenge` without enforcing it, and this server would
      // otherwise exchange any deposited code for whoever holds the relay id.
      if (!timingSafeEqual(s256(code_verifier), Buffer.from(relay.codeChallenge, 'base64url'))) {
        request.log.warn('OIDC sign-in with a PKCE verifier that does not match its challenge');

        return reply.status(401).send({ code: API_ERROR_OIDC_LOGIN_FAILED });
      }

      const code = relay.code;

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

        // The locale too, though optional: the provider's choice beats the interface's.
        if (isIncomplete(identity) || identity.locale === null) {
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

      const account = await resolveOidcAccount(
        env.OIDC_ISSUER,
        idClaims.sub,
        {
          email: identity.email,
          email_verified: identity.emailVerified,
          locale: identity.locale,
          first_name: identity.firstName,
          last_name: identity.lastName,
        },
        language
      );

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
