/**
 * Plumbing reused by every iframe submission handler that needs the user's ID
 * token (the Bearer credential of our API).
 *
 * The flow is:
 *   1. Handler calls `withFreshIdToken(getIdToken, (idToken) => apiCall(idToken))`.
 *   2. If `getIdToken()` returns null — the ID token reached its expiry — or the
 *      server answers 401 `unauthorized` — it no longer accepts it — the helper
 *      throws `SessionExpiredError`.
 *   3. The handler catches it and sets a local "session expired" flag.
 *   4. The UI renders <SessionExpiredAlert onReconnect={...}> which
 *      triggers `oidcAuth.requestAuth()` — opens a new tab to /login,
 *      the callback posts the new ID token back, the token changes, and
 *      a small effect in the handler clears the flag automatically.
 *
 * A sensitive action answered 401 `insufficient_user_authentication` (RFC 9470)
 * becomes `StepUpRequiredError` instead: the user is signed in, but has to
 * confirm with a fresh second-factor authentication (`oidcAuth.requestStepUp()`,
 * see useStepUp.ts) before retrying.
 *
 * Centralizing this means every future server-calling surface (not just
 * the onboarding modal) can reuse the same pattern with one import.
 */
import { API_ERROR_INSUFFICIENT_USER_AUTHENTICATION, API_ERROR_UNAUTHORIZED } from '@encryption/src/shared/error-codes';
import { ApiError } from '@encryption/src/ui/api/client';

/**
 * Thrown by `withFreshIdToken` when the ID token is gone. Handlers
 * distinguish this from other errors to show the Reconnect affordance.
 */
export class SessionExpiredError extends Error {
  constructor() {
    super('session_expired');
    this.name = 'SessionExpiredError';
  }
}

/** Thrown by `withFreshIdToken` when the action needs a step-up authentication first. */
export class StepUpRequiredError extends Error {
  constructor() {
    super('step_up_required');
    this.name = 'StepUpRequiredError';
  }
}

/**
 * Wrap an API call that needs a live ID token. Ensures a missing or rejected
 * one becomes an explicit, recoverable error instead of a silent skip or a
 * generic failure.
 */
export async function withFreshIdToken<T>(getIdToken: () => Promise<string | null>, fn: (idToken: string) => Promise<T>): Promise<T> {
  const idToken = await getIdToken();
  if (!idToken) {
    throw new SessionExpiredError();
  }

  try {
    return await fn(idToken);
  } catch (err) {
    // Only the ID token check answers `unauthorized`; the vault routes' own 401s
    // (a bad identity signature) carry codes of their own and stay errors.
    if (err instanceof ApiError && err.status === 401 && err.code === API_ERROR_UNAUTHORIZED) {
      throw new SessionExpiredError();
    }

    if (err instanceof ApiError && err.status === 401 && err.code === API_ERROR_INSUFFICIENT_USER_AUTHENTICATION) {
      throw new StepUpRequiredError();
    }

    throw err;
  }
}
