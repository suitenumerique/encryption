import type { FastifyReply, FastifyRequest } from 'fastify';

import type { IdTokenClaims } from '@encryption/src/server/auth/oidc-provider';
import { env } from '@encryption/src/server/env';
import { API_ERROR_INSUFFICIENT_USER_AUTHENTICATION } from '@encryption/src/shared/error-codes';

/**
 * Step-up authentication (RFC 9470) for the few actions where a stolen
 * password alone would do lasting harm, such as replacing a user's identity
 * (contacts would then encrypt to keys the thief holds).
 *
 * The proof is the ID token itself, the Bearer credential of every call: it
 * says how the user authenticated (`acr`, `amr`) and when (`auth_time`). An
 * action asks for a token that shows a second factor AND an authentication
 * younger than `OIDC_STEP_UP_MAX_AGE_SECONDS`. Without one, it answers 401
 * `insufficient_user_authentication`; the interface then has the user sign in
 * again with the provider asked for a fresh, second-factor authentication, and
 * the new ID token replaces the old one. Within the max age, further sensitive
 * actions pass without asking again; past it, the token still serves every
 * ordinary call until it expires.
 *
 * The claims are the provider's word: a second factor protects against a stolen
 * password, not against the provider itself.
 *
 * Off unless `OIDC_STEP_UP_ENABLED` (see env-schema.ts for why): every check
 * then passes, so no challenge is ever sent and the interface never asks.
 */

function stringList(value: unknown): string[] {
  if (typeof value === 'string') return [value];

  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

/**
 * Whether the provider says the user authenticated with a second factor. With
 * no accepted values configured at all, there is no policy to meet: true.
 */
export function hasSecondFactor(claims: Record<string, unknown>): boolean {
  if (env.OIDC_STEP_UP_ACR_VALUES.length === 0 && env.OIDC_STEP_UP_AMR_VALUES.length === 0) return true;

  const acr = typeof claims.acr === 'string' ? claims.acr : null;

  if (acr !== null && env.OIDC_STEP_UP_ACR_VALUES.includes(acr)) return true;

  return stringList(claims.amr).some((method) => env.OIDC_STEP_UP_AMR_VALUES.includes(method));
}

/** Whether the authentication behind the token is recent enough for a sensitive action. */
export function isFreshAuthentication(claims: Record<string, unknown>, now = Date.now()): boolean {
  if (typeof claims.auth_time !== 'number') return false;

  const ageSeconds = now / 1000 - claims.auth_time;

  // A small negative age is clock skew with the provider, not a future login.
  return ageSeconds >= -30 && ageSeconds <= env.OIDC_STEP_UP_MAX_AGE_SECONDS;
}

export function satisfiesStepUp(claims: Record<string, unknown>, now = Date.now()): boolean {
  if (!env.OIDC_STEP_UP_ENABLED) return true;

  return hasSecondFactor(claims) && isFreshAuthentication(claims, now);
}

/**
 * The RFC 9470 challenge: 401, `WWW-Authenticate: Bearer
 * error="insufficient_user_authentication"` with what would satisfy it, and our
 * usual error body carrying the same in `params`.
 */
export function sendStepUpChallenge(reply: FastifyReply): FastifyReply {
  const parameters = [
    'error="insufficient_user_authentication"',
    'error_description="A fresh authentication with a second factor is required"',
    ...(env.OIDC_STEP_UP_ACR_VALUES.length > 0 ? [`acr_values="${env.OIDC_STEP_UP_ACR_VALUES.join(' ')}"`] : []),
    `max_age="${env.OIDC_STEP_UP_MAX_AGE_SECONDS}"`,
  ];

  return reply
    .status(401)
    .header('www-authenticate', `Bearer ${parameters.join(', ')}`)
    .send({ code: API_ERROR_INSUFFICIENT_USER_AUTHENTICATION, params: { max_age: env.OIDC_STEP_UP_MAX_AGE_SECONDS } });
}

/**
 * For a route handler: true when the request's ID token satisfies the step-up,
 * otherwise sends the challenge and returns false (the handler then returns the
 * reply as is).
 */
export function requireStepUp(request: FastifyRequest, reply: FastifyReply): boolean {
  const claims: IdTokenClaims | undefined = request.idTokenClaims;

  if (claims && satisfiesStepUp(claims)) return true;

  request.log.info({ userId: request.userId }, 'sensitive action refused: step-up authentication required');
  sendStepUpChallenge(reply);

  return false;
}
