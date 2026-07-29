import { useCallback, useEffect, useRef, useState } from 'react';

import i18n from '@encryption/src/i18n';
import { OIDC_AUTH_MESSAGE_TYPE, getLoginUrl, isOidcConfigured } from '@encryption/src/ui/auth/oidc-client';
import type { TokenSet } from '@encryption/src/ui/auth/oidc-client';

interface OidcAuthState {
  /** The current access token, or null if not authenticated */
  token: string | null;
  /** The full token set (access + refresh + expiry), or null */
  tokenSet: TokenSet | null;
  /** The authenticated user's sub claim */
  userId: string | null;
  /** Whether the user is currently authenticated with valid tokens */
  isAuthenticated: boolean;
  /** Whether auth is needed but not yet initiated by the user */
  needsAuth: boolean;
  /** Whether waiting for the login tab to complete */
  isAuthenticating: boolean;
  /** Error message if authentication failed */
  error: string | null;
  /** Whether OIDC is configured (env vars present) */
  isConfigured: boolean;
  /** User clicks "Continue" — sends auth request to parent and starts listening */
  requestAuth: () => void;
  /** Update the token set (e.g. after a refresh) */
  updateTokenSet: (tokenSet: TokenSet) => void;
  /**
   * Drop the session after the IdP definitively rejected the refresh token.
   * Without this, a dead-but-present token keeps `needsAuth` false forever and
   * the UI never offers to sign in again.
   */
  clearTokenSet: () => void;
}

/**
 * React hook that manages OIDC authentication for the encryption interface iframe.
 *
 * The iframe cannot do OIDC itself (popups blocked, redirects blocked by IdP CSP).
 * Instead:
 * 1. Hook detects auth is needed → sets needsAuth=true
 * 2. UI shows an explanation + "Continue" button
 * 3. User clicks Continue to open a new tab to the login URL (provided by the iframe)
 * 4. Login tab → Keycloak → callback → postMessage back to opener (this iframe)
 * 5. This hook receives the message and stores the token
 */
export function useOidcAuth(expectedSuiteUserId: string | null): OidcAuthState {
  const [tokenSet, setTokenSet] = useState<TokenSet | null>(null);
  const [needsAuth, setNeedsAuth] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const waitingRef = useRef(false);
  const loginWindowRef = useRef<Window | null>(null);
  const windowPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Listen for postMessage from the callback tab (window.opener.postMessage)
  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      if (event.data?.type !== OIDC_AUTH_MESSAGE_TYPE || !event.data.tokenSet) return;
      if (event.origin !== window.location.origin) return;

      if (windowPollRef.current) clearInterval(windowPollRef.current);
      windowPollRef.current = null;
      loginWindowRef.current = null;
      setTokenSet(event.data.tokenSet as TokenSet);
      setIsAuthenticating(false);
      waitingRef.current = false;
    }

    window.addEventListener('message', handleMessage);

    return () => window.removeEventListener('message', handleMessage);
  }, []);

  const requestAuth = useCallback(() => {
    if (!isOidcConfigured() || !expectedSuiteUserId) return;
    if (waitingRef.current) return;

    const loginUrl = getLoginUrl(expectedSuiteUserId);
    const loginWindow = window.open(loginUrl, '_blank');

    // Popup blocked: there is no tab to wait on, so entering the "authenticating"
    // state would spin forever. Surface it as an error (with the sign-in screen's
    // Retry) instead of a dead loader, and keep `waitingRef` false so Retry works.
    if (!loginWindow) {
      setError(i18n.t('auth.popup_blocked'));
      setNeedsAuth(true);

      return;
    }

    loginWindowRef.current = loginWindow;

    waitingRef.current = true;
    setNeedsAuth(false);
    setIsAuthenticating(true);
    setError(null);

    // Poll the login window — if the user closes it manually, stop waiting
    windowPollRef.current = setInterval(() => {
      if (loginWindow.closed) {
        if (windowPollRef.current) clearInterval(windowPollRef.current);
        windowPollRef.current = null;
        loginWindowRef.current = null;

        if (waitingRef.current) {
          waitingRef.current = false;
          setIsAuthenticating(false);
          setNeedsAuth(true);
        }
      }
    }, 500);
  }, [expectedSuiteUserId]);

  // Setting the token set to null makes the effect below flip `needsAuth` back
  // on, so the UI returns to its "sign in" affordance instead of looking logged
  // in. Stable identity, so callers can list it in their dependency arrays.
  const clearTokenSet = useCallback(() => setTokenSet(null), []);

  // Detect that auth is needed, or that the current token is for the wrong user
  useEffect(() => {
    if (!isOidcConfigured() || !expectedSuiteUserId) return;

    if (tokenSet) {
      if (tokenSet.sub !== expectedSuiteUserId) {
        setTokenSet(null);
        setNeedsAuth(true);
        waitingRef.current = false;
      }

      return;
    }

    setNeedsAuth(true);
  }, [expectedSuiteUserId, tokenSet]);

  return {
    token: tokenSet?.accessToken ?? null,
    tokenSet,
    userId: tokenSet?.sub ?? null,
    isAuthenticated: tokenSet !== null,
    needsAuth,
    isAuthenticating,
    error,
    isConfigured: isOidcConfigured(),
    requestAuth,
    updateTokenSet: setTokenSet,
    clearTokenSet,
  };
}
