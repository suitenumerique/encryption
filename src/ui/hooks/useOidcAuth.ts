import { useCallback, useEffect, useRef, useState } from 'react';

import i18n from '@encryption/src/i18n';
import { isLocale } from '@encryption/src/shared/locale';
import { ApiError } from '@encryption/src/ui/api/client';
import {
  type IdTokenSet,
  type LoginOptions,
  OIDC_LOGIN_PARAMETERS_MESSAGE_TYPE,
  OIDC_LOGIN_READY_MESSAGE_TYPE,
  type SignIn,
  WrongUserError,
  createSignIn,
  exchangeSignIn,
  getLoginUrl,
} from '@encryption/src/ui/auth/login';

// How often the iframe asks whether the code arrived, the least time between two
// checks when the user's return asks for one early, and for how long at most (the
// server keeps a sign-in in flight for an hour).
const EXCHANGE_POLL_INTERVAL_MS = 5000;
const EXCHANGE_MIN_GAP_MS = 1000;
const SIGN_IN_LIFETIME_MS = 60 * 60 * 1000;

/**
 * Whether a failed check ends the sign-in. The server consumes a deposit at the
 * first check that finds it, so whatever it answers then is the outcome, and a
 * check after it would wait forever: anything our server answered ends it, even
 * an internal error. Only a request that never got its answer from our server
 * (no response at all, a gateway, a rate limit) is worth asking again.
 */
function isFinalExchangeError(err: unknown): boolean {
  if (err instanceof WrongUserError) return true;
  if (!(err instanceof ApiError)) return false;

  return err.status !== 0 && err.status !== 429 && err.status !== 502 && err.status !== 503 && err.status !== 504;
}

interface OidcAuthState {
  /** The provider's ID token, the Bearer credential for our API, or null if not authenticated */
  idToken: string | null;
  /** The ID token with its expiry and who it is for, or null */
  idTokenSet: IdTokenSet | null;
  /** Whether the user currently holds an ID token */
  isAuthenticated: boolean;
  /**
   * Whether the user came back to this window during a sign-in and the server is
   * being asked for its result: most likely they just finished in the sign-in
   * tab, so this is shown as "finishing", not as "complete it in the tab".
   */
  isConfirming: boolean;
  /** Whether auth is needed but not yet initiated by the user */
  needsAuth: boolean;
  /** Whether a sign-in tab is out and the iframe is waiting for its result */
  isAuthenticating: boolean;
  /** Error message if authentication failed */
  error: string | null;
  /** Whether the last sign-in was refused for being someone other than the product's user */
  wrongUser: boolean;
  /**
   * Opens the sign-in tab and waits for its result. Called again while
   * waiting, it drops the sign-in in flight and opens a new tab ("Open the
   * sign-in again"): the iframe cannot tell whether the previous tab is still
   * there. After a wrong-user refusal, asks the provider for credentials again.
   */
  requestAuth: () => void;
  /**
   * User confirms a sensitive action: opens the sign-in tab for a step-up (a
   * fresh authentication with a second factor, RFC 9470). The ID token it
   * brings back replaces the current one.
   */
  requestStepUp: () => void;
  /** Stop waiting for the sign-in in flight. */
  cancelAuth: () => void;
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
 * The iframe cannot sign in where it is (providers refuse to be framed), and the
 * tab it opens may lose its link to the iframe on a provider page that sends
 * COOP, so the result comes back through the server (see auth/login.ts):
 * 1. Hook detects auth is needed → sets needsAuth=true
 * 2. UI shows an explanation + "Continue" button
 * 3. User clicks Continue: the hook draws the sign-in, opens /login in a new tab
 *    and answers that tab's request for the parameters
 * 4. Tab → provider → callback, which deposits the code on the server
 * 5. Meanwhile the hook asks the server to exchange it, until the ID token comes
 *    back, the user cancels, or they open the sign-in again
 */
export function useOidcAuth(expectedSuiteUserId: string | null): OidcAuthState {
  const [idTokenSet, setIdTokenSet] = useState<IdTokenSet | null>(null);
  const [needsAuth, setNeedsAuth] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [isConfirming, setIsConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [wrongUser, setWrongUser] = useState(false);
  // Ends the sign-in in flight: its tab handshake and its polling.
  const stopAttemptRef = useRef<(() => void) | null>(null);

  const stopAttempt = useCallback(() => {
    stopAttemptRef.current?.();
    stopAttemptRef.current = null;
    setIsConfirming(false);
  }, []);

  useEffect(() => stopAttempt, [stopAttempt]);

  const openLoginTab = useCallback(
    (options: LoginOptions) => {
      if (!expectedSuiteUserId) return;

      stopAttempt();

      // Opened right away, inside the click: a window opened after an await is no
      // longer the user's gesture, and the browser blocks it.
      const loginWindow = window.open(getLoginUrl(), '_blank');

      // Popup blocked: there is no tab to wait on. Surface it as an error (with the
      // sign-in screen's Retry) instead of a dead loader. A step-up happens while
      // signed in: its failures leave the current ID token in place instead of
      // sending the user back to the sign-in screen.
      if (!loginWindow) {
        setIsAuthenticating(false);
        setError(i18n.t('auth.popup_blocked'));
        if (!options.stepUp) setNeedsAuth(true);

        return;
      }

      let active = true;
      let signIn: SignIn | null = null;
      const interfaceOrigin = window.location.origin;

      // The tab asks once it loaded, maybe before the sign-in below is drawn: it
      // is answered as soon as both are there.
      let tabReady = false;
      const answerTab = () => {
        if (active && tabReady && signIn) {
          loginWindow.postMessage({ type: OIDC_LOGIN_PARAMETERS_MESSAGE_TYPE, parameters: signIn.parameters }, interfaceOrigin);
        }
      };
      const onMessage = (event: MessageEvent) => {
        // Only the tab this attempt opened, on our own origin, gets the parameters.
        if (event.source !== loginWindow || event.origin !== interfaceOrigin) return;
        if ((event.data as { type?: string } | null)?.type !== OIDC_LOGIN_READY_MESSAGE_TYPE) return;

        tabReady = true;
        answerTab();
      };

      window.addEventListener('message', onMessage);

      if (!options.stepUp) setNeedsAuth(false);
      setIsAuthenticating(true);
      setError(null);
      setWrongUser(false);

      const settle = (outcome: () => void) => {
        if (!active) return;
        stopAttempt();
        setIsAuthenticating(false);
        outcome();
      };

      // When the server is asked: every few seconds, and as soon as the user comes
      // back to this window (most likely from the sign-in tab, so the result shows at
      // once), but never two requests at a time nor two within a second.
      const deadline = Date.now() + SIGN_IN_LIFETIME_MS;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let inFlight = false;
      let lastCheckAt = Date.now();

      const scheduleCheck = (delayMs: number) => {
        clearTimeout(timer);
        if (active) timer = setTimeout(() => void check(), delayMs);
      };

      const check = async () => {
        if (!active || inFlight) return;

        // The user came back before the sign-in was even drawn.
        if (!signIn) {
          scheduleCheck(EXCHANGE_POLL_INTERVAL_MS);

          return;
        }

        inFlight = true;
        lastCheckAt = Date.now();

        try {
          const result = await exchangeSignIn(signIn);

          if (result) {
            settle(() => setIdTokenSet(result));

            return;
          }

          // Not deposited yet: the user came back without finishing.
          setIsConfirming(false);
        } catch (err) {
          // The server never answered this one (network, a proxy, too many
          // requests): the next check asks again.
          if (!isFinalExchangeError(err)) {
            setIsConfirming(false);
            scheduleCheck(EXCHANGE_POLL_INTERVAL_MS);

            return;
          }

          settle(() => {
            if (err instanceof WrongUserError) setWrongUser(true);
            setError(err instanceof WrongUserError ? i18n.t('auth.wrong_user') : err instanceof Error ? err.message : String(err));
            if (!options.stepUp) setNeedsAuth(true);
          });

          return;
        } finally {
          inFlight = false;
        }

        if (Date.now() >= deadline) {
          settle(() => {
            if (!options.stepUp) setNeedsAuth(true);
          });

          return;
        }

        scheduleCheck(EXCHANGE_POLL_INTERVAL_MS);
      };

      const onReturn = () => {
        if (document.visibilityState !== 'visible' || inFlight || !signIn) return;

        setIsConfirming(true);
        scheduleCheck(Math.max(0, lastCheckAt + EXCHANGE_MIN_GAP_MS - Date.now()));
      };

      document.addEventListener('visibilitychange', onReturn);
      window.addEventListener('focus', onReturn);
      stopAttemptRef.current = () => {
        active = false;
        clearTimeout(timer);
        window.removeEventListener('message', onMessage);
        document.removeEventListener('visibilitychange', onReturn);
        window.removeEventListener('focus', onReturn);
      };

      void (async () => {
        const language = isLocale(i18n.resolvedLanguage) ? i18n.resolvedLanguage : undefined;

        signIn = await createSignIn(expectedSuiteUserId, { ...options, language });
        answerTab();
        scheduleCheck(EXCHANGE_POLL_INTERVAL_MS);
      })();
    },
    [expectedSuiteUserId, stopAttempt]
  );

  const cancelAuth = useCallback(() => {
    stopAttempt();
    setIsAuthenticating(false);
  }, [stopAttempt]);

  const requestAuth = useCallback(() => openLoginTab({ forceLogin: wrongUser }), [openLoginTab, wrongUser]);
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
    isConfirming,
    error,
    wrongUser,
    requestAuth,
    requestStepUp,
    cancelAuth,
    updateIdTokenSet: setIdTokenSet,
    clearIdTokenSet,
  };
}
