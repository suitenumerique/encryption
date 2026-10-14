import { useCallback, useEffect, useRef, useState } from 'react';

import i18n from '@encryption/src/i18n';
import {
  type IdTokenSet,
  type LoginOptions,
  OIDC_AUTH_ACK_MESSAGE_TYPE,
  OIDC_AUTH_MESSAGE_TYPE,
  getLoginUrl,
  idTokenSetSchema,
} from '@encryption/src/ui/auth/login';

interface OidcAuthState {
  /** The provider's ID token, the Bearer credential for our API, or null if not authenticated */
  idToken: string | null;
  /** The ID token with its expiry and who it is for, or null */
  idTokenSet: IdTokenSet | null;
  /** Whether the user currently holds an ID token */
  isAuthenticated: boolean;
  /** Whether auth is needed but not yet initiated by the user */
  needsAuth: boolean;
  /** Whether waiting for the login tab to complete */
  isAuthenticating: boolean;
  /** Error message if authentication failed */
  error: string | null;
  /** User clicks "Continue" — opens the login tab and starts listening */
  requestAuth: () => void;
  /**
   * User confirms a sensitive action — opens the login tab for a step-up (a
   * fresh authentication with a second factor, RFC 9470). The ID token it
   * brings back replaces the current one.
   */
  requestStepUp: () => void;
  /** Adopt an ID token (e.g. one restored from storage) */
  updateIdTokenSet: (idTokenSet: IdTokenSet) => void;
  /**
   * Drop the ID token once it expired or the server rejected it. Without this, a
   * dead-but-present token keeps `needsAuth` false forever and the UI never
   * offers to sign in again.
   */
  clearIdTokenSet: () => void;
}

/**
 * React hook that manages OIDC authentication for the encryption interface iframe.
 *
 * The iframe cannot do OIDC itself (popups blocked, redirects blocked by IdP CSP).
 * Instead:
 * 1. Hook detects auth is needed → sets needsAuth=true
 * 2. UI shows an explanation + "Continue" button
 * 3. User clicks Continue to open a new tab to the login URL (provided by the iframe)
 * 4. Login tab → provider → callback → server verifies and returns the ID token →
 *    postMessage back to opener (this iframe)
 * 5. This hook receives the message and keeps the ID token
 */
export function useOidcAuth(expectedSuiteUserId: string | null): OidcAuthState {
  const [idTokenSet, setIdTokenSet] = useState<IdTokenSet | null>(null);
  const [needsAuth, setNeedsAuth] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const waitingRef = useRef(false);
  const loginWindowRef = useRef<Window | null>(null);
  const windowPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Listen for postMessage from the callback tab (window.opener.postMessage)
  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      if (event.data?.type !== OIDC_AUTH_MESSAGE_TYPE) return;
      if (event.origin !== window.location.origin) return;

      const received = idTokenSetSchema.safeParse(event.data.idTokenSet);

      if (!received.success) return;

      // Tell the callback tab it may close. Sent synchronously so it lands inside the
      // window `notifyAuthComplete` is waiting on, and addressed to our own origin so
      // it cannot be observed by whatever else may have opened that tab.
      event.source?.postMessage({ type: OIDC_AUTH_ACK_MESSAGE_TYPE }, { targetOrigin: window.location.origin });

      if (windowPollRef.current) clearInterval(windowPollRef.current);
      windowPollRef.current = null;
      loginWindowRef.current = null;
      setIdTokenSet(received.data);
      setIsAuthenticating(false);
      waitingRef.current = false;
    }

    window.addEventListener('message', handleMessage);

    return () => window.removeEventListener('message', handleMessage);
  }, []);

  const openLoginTab = useCallback(
    (options: LoginOptions) => {
      if (!expectedSuiteUserId) return;
      if (waitingRef.current) return;

      const loginUrl = getLoginUrl(expectedSuiteUserId, options);
      const loginWindow = window.open(loginUrl, '_blank');

      // Popup blocked: there is no tab to wait on, so entering the "authenticating"
      // state would spin forever. Surface it as an error (with the sign-in screen's
      // Retry) instead of a dead loader, and keep `waitingRef` false so Retry works.
      // A step-up happens while signed in: its failures leave the current ID
      // token in place instead of sending the user back to the sign-in screen.
      if (!loginWindow) {
        setError(i18n.t('auth.popup_blocked'));
        if (!options.stepUp) setNeedsAuth(true);

        return;
      }

      loginWindowRef.current = loginWindow;

      waitingRef.current = true;
      if (!options.stepUp) setNeedsAuth(false);
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
            if (!options.stepUp) setNeedsAuth(true);
          }
        }
      }, 500);
    },
    [expectedSuiteUserId]
  );

  const requestAuth = useCallback(() => openLoginTab({}), [openLoginTab]);
  const requestStepUp = useCallback(() => openLoginTab({ stepUp: true }), [openLoginTab]);

  // Setting the ID token to null makes the effect below flip `needsAuth` back
  // on, so the UI returns to its "sign in" affordance instead of looking logged
  // in. Stable identity, so callers can list it in their dependency arrays.
  const clearIdTokenSet = useCallback(() => setIdTokenSet(null), []);

  // Detect that auth is needed, or that the current ID token is for the wrong user
  useEffect(() => {
    if (!expectedSuiteUserId) return;

    if (idTokenSet) {
      if (idTokenSet.sub !== expectedSuiteUserId) {
        setIdTokenSet(null);
        setNeedsAuth(true);
        waitingRef.current = false;
      }

      return;
    }

    setNeedsAuth(true);
  }, [expectedSuiteUserId, idTokenSet]);

  return {
    idToken: idTokenSet?.idToken ?? null,
    idTokenSet,
    isAuthenticated: idTokenSet !== null,
    needsAuth,
    isAuthenticating,
    error,
    requestAuth,
    requestStepUp,
    updateIdTokenSet: setIdTokenSet,
    clearIdTokenSet,
  };
}
