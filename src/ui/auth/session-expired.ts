/**
 * Session-expired plumbing reused by every iframe submission handler that
 * needs a fresh OIDC token.
 *
 * The flow is:
 *   1. Handler calls `withFreshToken(getToken, (token) => apiCall(token))`.
 *   2. If `getToken()` returns null — meaning the refresh-token grant
 *      failed against Keycloak, typically because the SSO session idled
 *      out — the helper throws `SessionExpiredError`.
 *   3. The handler catches it and sets a local "session expired" flag.
 *   4. The UI renders <SessionExpiredAlert onReconnect={...}> which
 *      triggers `oidcAuth.requestAuth()` — opens a new tab to /login,
 *      the callback posts the fresh token back, `tokenSet` updates, and
 *      a small effect in the handler clears the flag automatically.
 *
 * Centralizing this means every future server-calling surface (not just
 * the onboarding modal) can reuse the same pattern with one import.
 */

/**
 * Thrown by `withFreshToken` when the OIDC refresh fails. Handlers
 * distinguish this from other errors to show the Reconnect affordance.
 */
export class SessionExpiredError extends Error {
  constructor() {
    super('session_expired');
    this.name = 'SessionExpiredError';
  }
}

/**
 * Wrap an API call that needs a fresh access token. Ensures a null token
 * becomes an explicit, recoverable error instead of a silent skip.
 */
export async function withFreshToken<T>(
  getToken: () => Promise<string | null>,
  fn: (token: string) => Promise<T>,
): Promise<T> {
  const token = await getToken();
  if (!token) {
    throw new SessionExpiredError();
  }
  return fn(token);
}
