/**
 * OIDC client for the encryption interface.
 * Uses oidc-client-ts for Authorization Code flow with PKCE via redirect.
 *
 * The auth flow happens in a NEW TAB (not the iframe):
 * 1. The iframe detects it needs auth and calls `window.open` on /login itself
 * 2. That tab redirects to Keycloak for authentication
 * 3. Keycloak redirects back to /auth/callback on the encryption domain
 * 4. The callback page posts the token set to `window.opener`, which is the iframe
 * 5. The callback page closes itself, and the iframe proceeds
 */
import { User, UserManager, WebStorageStateStore } from 'oidc-client-ts';
import { z } from 'zod';

import '@encryption/src/shared/zod-jitless';
import { runtimeConfig } from '@encryption/src/ui/runtime-config';

const OIDC_ISSUER = runtimeConfig.oidcIssuer;
const OIDC_CLIENT_ID = runtimeConfig.oidcClientId;
const OIDC_REDIRECT_URI = runtimeConfig.oidcRedirectUri;

export const OIDC_AUTH_MESSAGE_TYPE = 'encryption-oidc-auth-complete';
export const OIDC_AUTH_ACK_MESSAGE_TYPE = 'encryption-oidc-auth-ack';

const AUTH_ACK_TIMEOUT_MS = 5000;

export const tokenSetSchema = z.object({
  accessToken: z.string(),
  refreshToken: z.string().nullable(),
  idToken: z.string().nullable(),
  expiresAt: z.number(), // Unix timestamp in ms
  sub: z.string(),
});
export type TokenSet = z.infer<typeof tokenSetSchema>;

// The subset of JWT claims we read. z.object strips unknown keys, so the many
// other claims a token carries pass through harmlessly; all are optional because
// the OIDC provider decides which it emits.
export const jwtClaimsSchema = z.object({
  sub: z.string().optional(),
  name: z.string().optional(),
  preferred_username: z.string().optional(),
  email: z.string().optional(),
});
export type JwtClaims = z.infer<typeof jwtClaimsSchema>;

/** Decode + validate a JWT's claims without verifying the signature (the server
 *  already validated the token). Returns null on any malformed input. */
export function decodeJwtClaims(token: string): JwtClaims | null {
  try {
    return jwtClaimsSchema.parse(JSON.parse(atob(token.split('.')[1])));
  } catch {
    return null;
  }
}

let userManager: UserManager | null = null;

function getUserManager(): UserManager {
  if (userManager) return userManager;

  if (!OIDC_ISSUER || !OIDC_CLIENT_ID || !OIDC_REDIRECT_URI) {
    throw new Error('OIDC not configured');
  }

  // Use sessionStorage for both state and user store.
  // The auth flow happens in a new tab — sessionStorage is per-tab,
  // but the login tab and callback tab are the same tab (redirect).
  // After auth, the tokens are sent to the vault and broadcast to other tabs.
  userManager = new UserManager({
    authority: OIDC_ISSUER,
    client_id: OIDC_CLIENT_ID,
    redirect_uri: OIDC_REDIRECT_URI,
    scope: 'openid profile email',
    response_type: 'code',
    automaticSilentRenew: false,
    userStore: new WebStorageStateStore({ store: sessionStorage }),
    stateStore: new WebStorageStateStore({ store: sessionStorage }),
  });

  return userManager;
}

function userToTokenSet(user: User): TokenSet {
  return {
    accessToken: user.access_token,
    refreshToken: user.refresh_token ?? null,
    idToken: user.id_token ?? null,
    expiresAt: (user.expires_at ?? 0) * 1000,
    sub: user.profile.sub,
  };
}

// --- Login page (new tab) ---

/**
 * Start the OIDC redirect flow. Called from the /login page in the new tab.
 * @param expectedSub - If provided, stored in the OIDC state parameter (survives the
 *   redirect round-trip) so the callback can verify the authenticated sub matches.
 * @param forceLogin - If true, passes prompt=login to Keycloak to force re-authentication
 *   even if there's an existing SSO session (used when the wrong account was detected).
 */
export async function startLogin(expectedSub?: string, forceLogin = false): Promise<void> {
  const userManager = getUserManager();

  const extraQueryParams: Record<string, string> = {};

  if (forceLogin) {
    extraQueryParams.prompt = 'login';
  }

  await userManager.signinRedirect({
    // The state data survives the redirect round-trip to Keycloak and back.
    // oidc-client-ts returns it as user.state in the callback.
    state: expectedSub ? { expectedSub } : undefined,
    extraQueryParams: Object.keys(extraQueryParams).length > 0 ? extraQueryParams : undefined,
  });
}

export class WrongUserError extends Error {
  expectedSub: string;

  constructor(expectedSub: string) {
    super('wrong_user');
    this.name = 'WrongUserError';
    this.expectedSub = expectedSub;
  }
}

/**
 * Handle the OIDC callback. Called from the /auth/callback page in the new tab.
 * Verifies the authenticated sub matches the expected one (stored in OIDC state).
 * Returns the TokenSet on success.
 * Throws WrongUserError if the authenticated user doesn't match the expected one.
 */
export async function handleCallback(): Promise<TokenSet> {
  const userManager = getUserManager();
  const user = await userManager.signinRedirectCallback();
  const tokenSet = userToTokenSet(user);

  // The expectedSub was stored in the OIDC state parameter during startLogin().
  // It survives the Keycloak redirect round-trip without needing sessionStorage.
  const stateData = user.state as { expectedSub?: string } | undefined;
  const expectedSub = stateData?.expectedSub;

  if (expectedSub && tokenSet.sub !== expectedSub) {
    throw new WrongUserError(expectedSub);
  }

  return tokenSet;
}

/**
 * Send auth completion back to the opener (the interface iframe), and resolve to
 * whether that opener acknowledged it.
 *
 * The `interfaceOrigin` second argument is the security boundary, not a formality:
 * the browser compares it against the opener's CURRENT origin and drops the message
 * on mismatch. Any page can open this flow in a popup, so replacing it with '*' would
 * hand the full token set, refresh token included, to whoever opened the tab.
 *
 * The acknowledgement exists because the token set is otherwise posted blind. Only a
 * document on our own origin can send it, so a foreign opener never produces one and
 * the tab stays open instead of closing on a timer. That removes a signal an attacker
 * could otherwise read off `window.closed` — the tab closed only when the signed-in
 * `sub` matched the one they put in the URL — and it also stops a legitimate user from
 * being left silently unauthenticated when the message reached nobody.
 *
 * Uses window.opener.postMessage(): the callback tab was opened via window.open()
 * from the interface iframe. This works cross-site because it is a direct window
 * reference, not a storage API subject to Chrome's storage partitioning, which is
 * why a BroadcastChannel cannot replace it (the tab and the iframe sit in different
 * storage partitions). The opener reference is therefore load-bearing, and it is why
 * the server omits COOP on /login and /auth/callback: any COOP on those documents
 * severs it during the Keycloak round trip.
 */
export function notifyAuthComplete(tokenSet: TokenSet): Promise<boolean> {
  if (!window.opener || !OIDC_REDIRECT_URI) return Promise.resolve(false);

  const interfaceOrigin = new URL(OIDC_REDIRECT_URI).origin;

  return new Promise((resolve) => {
    function settle(acknowledged: boolean) {
      clearTimeout(timer);
      window.removeEventListener('message', onMessage);
      resolve(acknowledged);
    }

    function onMessage(event: MessageEvent) {
      if (event.origin !== interfaceOrigin || (event.data as { type?: string } | null)?.type !== OIDC_AUTH_ACK_MESSAGE_TYPE) return;

      settle(true);
    }

    const timer = setTimeout(() => settle(false), AUTH_ACK_TIMEOUT_MS);

    // Listening BEFORE posting: the interface answers synchronously in its own message
    // handler, so a listener registered afterwards can miss the acknowledgement.
    window.addEventListener('message', onMessage);
    window.opener.postMessage({ type: OIDC_AUTH_MESSAGE_TYPE, tokenSet }, interfaceOrigin);
  });
}

/**
 * Check if the OIDC client is configured (env vars present).
 */
export function isOidcConfigured(): boolean {
  return Boolean(OIDC_ISSUER && OIDC_CLIENT_ID && OIDC_REDIRECT_URI);
}

/**
 * Get the login URL that the parent should open in a new tab.
 * @param forceLogin - If true, adds prompt=login to force re-authentication
 */
export function getLoginUrl(expectedSub?: string, forceLogin = false): string {
  const base = OIDC_REDIRECT_URI?.replace('/auth/callback', '/login') ?? '/login';
  const params = new URLSearchParams();

  if (expectedSub) params.set('expectedSub', expectedSub);
  if (forceLogin) params.set('forceLogin', '1');

  const qs = params.toString();

  return qs ? `${base}?${qs}` : base;
}

// --- Token refresh ---

const TOKEN_REFRESH_BUFFER_MS = 60_000; // Refresh if token expires within 1 minute

/**
 * Check if a token needs to be refreshed (expires within the buffer period).
 */
export function tokenNeedsRefresh(tokenSet: TokenSet): boolean {
  return tokenSet.expiresAt - Date.now() < TOKEN_REFRESH_BUFFER_MS;
}

function decodeJwtSub(token: string): string | undefined {
  return decodeJwtClaims(token)?.sub;
}

/**
 * The IdP definitively rejected the refresh token: it is dead for good (idle
 * timeout, revoked session, realm or database reset). Callers MUST distinguish
 * this from a transient failure (offline, 5xx), because only this one may drop
 * the stored session; clearing on a hiccup would sign the user out every time
 * the IdP stumbles.
 */
export class InvalidGrantError extends Error {
  constructor() {
    super('invalid_grant');
    this.name = 'InvalidGrantError';
  }
}

/**
 * Refresh the access token using the refresh token.
 * Calls the OIDC token endpoint directly (standard refresh_token grant).
 */
async function doRefresh(refreshToken: string): Promise<TokenSet> {
  if (!OIDC_ISSUER || !OIDC_CLIENT_ID) {
    throw new Error('OIDC not configured');
  }

  const response = await fetch(`${OIDC_ISSUER}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: OIDC_CLIENT_ID,
      refresh_token: refreshToken,
    }),
  });

  if (!response.ok) {
    // OAuth 2 returns 400 (invalid_grant) for a token the IdP will never
    // accept again; 401 is the same verdict from a stricter deployment.
    if (response.status === 400 || response.status === 401) {
      throw new InvalidGrantError();
    }

    throw new Error(`Token refresh failed: ${response.status}`);
  }

  const data = await response.json();
  const sub = decodeJwtSub(data.access_token);

  if (!sub) {
    throw new Error('Refreshed token has no sub claim');
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token ?? refreshToken,
    idToken: data.id_token ?? null,
    expiresAt: Date.now() + data.expires_in * 1000,
    sub,
  };
}

/**
 * Refresh the access token with a cross-tab mutex (Web Locks API).
 * Prevents concurrent refreshes when multiple product tabs embed the interface.
 *
 * @param currentTokenSet - The current token set (may be expired)
 * @param readStoredToken - Callback to read the latest token from storage
 *   (another tab may have already refreshed it while we were waiting for the lock)
 * @param persistToken - Callback to persist the refreshed token to storage. It is
 *   invoked INSIDE the lock, immediately after a successful refresh and before the
 *   lock is released, so a second tab acquiring the lock next reads the rotated
 *   token instead of the stale one. Persisting after releasing the lock (e.g. via a
 *   later React effect) lets a second tab refresh again with an already-consumed
 *   refresh token, causing a spurious "session expired" under Keycloak rotation.
 * @returns The refreshed token set
 */
export async function refreshTokenWithLock(
  currentTokenSet: TokenSet,
  readStoredToken: () => Promise<TokenSet | null>,
  persistToken: (tokenSet: TokenSet) => void
): Promise<TokenSet> {
  if (!currentTokenSet.refreshToken) {
    throw new Error('No refresh token available');
  }

  return navigator.locks.request('encryption-oidc-token-refresh', async () => {
    // Re-read from storage — another tab may have refreshed while we waited for the lock
    const stored = await readStoredToken();

    if (stored && !tokenNeedsRefresh(stored)) {
      return stored;
    }

    // Still expired — do the actual refresh
    const refreshToken = stored?.refreshToken ?? currentTokenSet.refreshToken;
    const refreshed = await doRefresh(refreshToken!);

    // Make storage authoritative under the lock, before releasing it.
    persistToken(refreshed);

    return refreshed;
  });
}
