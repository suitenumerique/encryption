import { Alert, Button, CunninghamProvider, Loader, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import {
  MSG_INTERFACE_CLOSED,
  MSG_INTERFACE_ONBOARDING_COMPLETE,
  MSG_INTERFACE_SET_THEME,
  MSG_INTERFACE_VERIFY_COMPLETE,
} from '@encryption/src/shared/constants';
import { fetchMe, fetchPublicKeysBySubs } from '@encryption/src/ui/api/server-client';
import { CallbackPage } from '@encryption/src/ui/auth/CallbackPage';
import { LoginPage } from '@encryption/src/ui/auth/LoginPage';
import { InvalidGrantError, type TokenSet, decodeJwtClaims, refreshTokenWithLock, tokenNeedsRefresh } from '@encryption/src/ui/auth/oidc-client';
import { clearToken, readToken, storeToken } from '@encryption/src/ui/auth/token-storage';
import { checkBrowserVersion } from '@encryption/src/ui/browser-check';
import { DeviceApproval } from '@encryption/src/ui/components/DeviceApproval';
import { EncryptionSettings } from '@encryption/src/ui/components/EncryptionSettings';
import { ModalEncryptionOnboarding } from '@encryption/src/ui/components/ModalEncryptionOnboarding';
import { RecipientProfile } from '@encryption/src/ui/components/RecipientProfile';
import { VerifyRecipients } from '@encryption/src/ui/components/VerifyRecipients';
import { TechnicalDocsPage } from '@encryption/src/ui/docs/TechnicalDocsPage';
import { UserDocsPage } from '@encryption/src/ui/docs/UserDocsPage';
import { useOidcAuth } from '@encryption/src/ui/hooks/useOidcAuth';
import { useParentMessages } from '@encryption/src/ui/hooks/useParentMessages';
import { EncryptionProvider, useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';
import { PATH_FOR_ROUTE, type Route, getRouteFromPath } from '@encryption/src/ui/routes';

const runtimeAppConfig = (window as unknown as { __ENCRYPTION_CONFIG__?: { docsEnabled?: boolean } }).__ENCRYPTION_CONFIG__;
const DOCS_ENABLED = runtimeAppConfig?.docsEnabled ?? true;

function getHashParams(): URLSearchParams {
  return new URLSearchParams(window.location.hash.slice(1));
}

/**
 * Get the Cunningham theme name from the URL hash.
 * The parent passes it via the hash: /onboarding#theme=dsfr
 * Default: "default" (white label light theme).
 */
function getThemeFromHash(): string {
  return getHashParams().get('theme') || 'default';
}

function getLangFromHash(): string | null {
  return getHashParams().get('lang');
}

/** Send a result back to the parent frame */
function notifyParent(parentOrigin: string | null, type: string, data?: Record<string, unknown>) {
  if (window.parent !== window && parentOrigin) {
    window.parent.postMessage({ type, ...data }, parentOrigin);
  }
}

export interface UserInfo {
  name: string | null;
  email: string | null;
}

/** Decode JWT payload to extract user identity (name, email). */
function decodeJwtUserInfo(token: string): UserInfo {
  const claims = decodeJwtClaims(token);

  return {
    name: claims?.name || claims?.preferred_username || null,
    email: claims?.email || null,
  };
}

/** Inner component that has access to the EncryptionContext */
function InterfaceRoutes({ route, navigate }: { route: Route; navigate: (to: Route) => void }) {
  const parentContext = useParentMessages();
  const { t } = useTranslation('common');
  const { setAuthInfo, hasKeys, isReady, resolveInternalUser } = useEncryptionContext();

  // The INTERNAL encryption user id. Resolved vault-first (alias store /
  // registry, no OIDC session needed, so settings work with an expired token),
  // with /api/me as the fallback for a never-onboarded user. It is what the
  // vault operates under and what binding signatures embed; components wait on
  // it (nullable userId props).
  const [internalUserId, setInternalUserId] = useState<string | null>(null);

  // Set auth info on the encryption context FIRST — the vault needs this before
  // we can make any requests (including token restoration). Re-sent when the
  // internal id lands so subsequent vault requests carry it.
  useEffect(() => {
    if (parentContext.suiteUserId) {
      setAuthInfo(parentContext.suiteUserId, internalUserId);
    }
  }, [parentContext.suiteUserId, internalUserId, setAuthInfo]);

  // Navigation guard: the setup/restore screens make no sense once this device
  // already holds keys, so redirect to settings if we land on them with a vault
  // present. Redirect only, no render gate: onboarding shows normally and we
  // simply navigate away when keys are found, so a slow/hung vault call can never
  // strand us on a loader.
  //
  // Evaluated ONCE per arrival (tracked by a ref) so it never re-guards a page we
  // already entered: a fresh onboarding mints keys mid-flow, and a host context
  // re-send must not trigger a redirect out of the backup/success step.
  const guardedRoute = useRef<Route | null>(null);

  useEffect(() => {
    if (route !== 'onboarding' && route !== 'restore') {
      guardedRoute.current = null;

      return;
    }
    if (guardedRoute.current === route) return;
    if (!parentContext.suiteUserId) return;

    guardedRoute.current = route;
    let cancelled = false;
    hasKeys()
      .then(({ hasKeys: has }) => {
        if (!cancelled && has) navigate('settings');
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
    // Intentionally NOT depending on live key state — this is an arrival guard.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [route, parentContext.suiteUserId]);

  // OIDC self-authentication: the interface obtains its own token.
  const oidcAuth = useOidcAuth(parentContext.suiteUserId);
  // Both are stable across renders (a state setter and a memoized callback), so
  // depending on them directly keeps the effects below honest about what they
  // use without re-running them on every render — which listing the whole
  // `oidcAuth` object would do.
  const { updateTokenSet, clearTokenSet } = oidcAuth;

  // Restore token from interface's own localStorage (not the vault).
  // This avoids re-authentication when the iframe is recreated (page refresh, modal close/open).
  const [tokenRestoreAttempted, setTokenRestoreAttempted] = useState(false);

  useEffect(() => {
    if (!parentContext.suiteUserId || oidcAuth.token) return;

    const stored = readToken(parentContext.suiteUserId);

    if (stored && stored.sub === parentContext.suiteUserId) {
      updateTokenSet(stored);
    }

    setTokenRestoreAttempted(true);
  }, [parentContext.suiteUserId, oidcAuth.token, updateTokenSet]);

  // Persist token set in localStorage after auth or refresh
  useEffect(() => {
    if (!oidcAuth.tokenSet || !parentContext.suiteUserId) return;

    storeToken(parentContext.suiteUserId, oidcAuth.tokenSet);
  }, [oidcAuth.tokenSet, parentContext.suiteUserId]);

  // Lazy token refresh: returns a valid token, refreshing if needed.
  // Uses Web Locks to prevent concurrent refreshes across tabs.
  const getValidToken = useCallback(async (): Promise<string | null> => {
    const currentTokenSet = oidcAuth.tokenSet;

    if (!currentTokenSet) return null;

    if (!tokenNeedsRefresh(currentTokenSet)) {
      return currentTokenSet.accessToken;
    }

    if (!currentTokenSet.refreshToken) return null;

    try {
      const readStoredToken = async (): Promise<TokenSet | null> => {
        return parentContext.suiteUserId ? readToken(parentContext.suiteUserId) : null;
      };

      const persistToken = (tokenSet: TokenSet) => {
        if (parentContext.suiteUserId) {
          storeToken(parentContext.suiteUserId, tokenSet);
        }
      };

      const refreshed = await refreshTokenWithLock(currentTokenSet, readStoredToken, persistToken);
      updateTokenSet(refreshed);

      return refreshed.accessToken;
    } catch (err) {
      // A definitively rejected refresh token (idle timeout, revoked session,
      // a reset Keycloak realm) must be evicted from memory AND localStorage.
      // Keeping it wedges the interface for good: the stale access token still
      // reads as "authenticated", so `needsAuth` stays false, no sign-in is
      // offered, and the restore-from-localStorage effect resurrects the same
      // dead token on every reload. Transient failures (offline, 5xx) fall
      // through untouched so a network hiccup never logs the user out.
      if (err instanceof InvalidGrantError) {
        if (parentContext.suiteUserId) {
          clearToken(parentContext.suiteUserId);
        }

        clearTokenSet();
      }

      return null;
    }
  }, [oidcAuth.tokenSet, parentContext.suiteUserId, updateTokenSet, clearTokenSet]);

  // OIDC token for server API calls. Components use oidcToken for display/checks,
  // but must call getValidToken() before actual API calls to ensure the token
  // is fresh (lazy refresh with Web Locks mutex if it expires within 1 minute).
  const oidcToken = oidcAuth.token;

  // Resolve the internal user id, vault first: the alias/registry chain needs
  // no OIDC session, so an onboarded user gets their id (and a working
  // settings page) even with an expired token. /api/me is the fallback for a
  // never-onboarded user only: it mints the server-side user row, which must
  // exist before onboarding can sign a key registration (the internal id is
  // inside the binding signature), and onboarding needs a live session anyway.
  useEffect(() => {
    if (!isReady || internalUserId) return;

    let cancelled = false;

    (async () => {
      try {
        const resolved = await resolveInternalUser();

        if (cancelled) return;
        if (resolved) {
          setInternalUserId(resolved);

          return;
        }
      } catch {
        // Vault unavailable: fall through to /api/me below.
      }

      if (!oidcToken) return;

      try {
        const token = await getValidToken();
        const me = token ? await fetchMe(token) : null;

        if (!cancelled && me) setInternalUserId(me.userId);
      } catch (err) {
        // Not an error condition for the page: an expired session only matters
        // if the user turns out to need onboarding, which will ask them to
        // sign in through its own flow.
        console.warn('[encryption-ui] Failed to resolve internal user id:', err);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [isReady, oidcToken, internalUserId, getValidToken, resolveInternalUser]);

  // Seed the vault's persistent alias store once the id is known: the request
  // envelope carries the internal id (setAuthInfo above re-ran), the vault
  // adopts it and persists the sub -> id alias, so the NEXT interface visit
  // resolves offline and token-free even if this one never touched the vault.
  const aliasSeededRef = useRef(false);

  useEffect(() => {
    if (!internalUserId || !isReady || aliasSeededRef.current) return;

    aliasSeededRef.current = true;
    resolveInternalUser().catch(() => {
      // Best-effort: the alias also gets written by any later vault request.
    });
  }, [internalUserId, isReady, resolveInternalUser]);

  const [hasExistingBackendKey, setHasExistingBackendKey] = useState(false);
  const [existingKeyFingerprint, setExistingKeyFingerprint] = useState<string | null>(null);

  // Lets a screen (e.g. settings) push into device-approval in place without a
  // real navigation, then return to where it was.
  const [routeOverride, setRouteOverride] = useState<Route | null>(null);
  const activeRoute = routeOverride ?? route;

  const userInfo = useMemo<UserInfo | null>(() => {
    if (!oidcToken) return null;

    return decodeJwtUserInfo(oidcToken);
  }, [oidcToken]);

  // Check for existing backend keys, to route the user to restore instead of
  // fresh onboarding. Queried by sub because that is the only id the parent
  // context guarantees, through the unauthenticated directory form, so it
  // works with no (or an expired) OIDC session, like resolution above.
  useEffect(() => {
    if (!parentContext.suiteUserId) return;

    fetchPublicKeysBySubs([parentContext.suiteUserId])
      .then(async (keys) => {
        setHasExistingBackendKey(keys.length > 0);

        if (keys.length > 0) {
          // The fingerprint users verify out-of-band is the IDENTITY
          // (signature) key, not the encryption key.
          const fp = await computeKeyFingerprint(keys[0].signature_public_key);
          setExistingKeyFingerprint(fp);
        }
      })
      .catch((err) => {
        console.warn('[encryption-ui] Failed to check for existing backend keys:', err);
      });
  }, [parentContext.suiteUserId]);

  const handleOnboardingSuccess = useCallback(
    (publicKey: string) => {
      notifyParent(parentContext.parentOrigin, MSG_INTERFACE_ONBOARDING_COMPLETE, { publicKey });
    },
    [parentContext.parentOrigin]
  );

  const handleClose = useCallback(() => {
    notifyParent(parentContext.parentOrigin, MSG_INTERFACE_CLOSED);
  }, [parentContext.parentOrigin]);

  // All hooks declared above — conditional returns are safe below this point.
  // OIDC must be configured for the interface to work.
  if (!oidcAuth.isConfigured) {
    return (
      <div style={{ padding: '2rem', maxWidth: '480px', margin: '0 auto' }}>
        <Alert type={VariantType.ERROR}>{t('auth.oidc_not_configured')}</Alert>
      </div>
    );
  }

  // Show a loader while trying to restore a token from the vault.
  // This prevents a flash of the "Authentication required" screen.
  if (!oidcAuth.token && !tokenRestoreAttempted) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '200px' }}>
        <Loader />
      </div>
    );
  }

  // Wait for OIDC authentication.
  if (!oidcAuth.token) {
    // Waiting for the login tab to complete
    if (oidcAuth.isAuthenticating) {
      return (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'center',
            minHeight: '200px',
            gap: '1rem',
            padding: '2rem',
          }}
        >
          <Loader />
          <p style={{ textAlign: 'center', margin: 0 }}>{t('auth.authenticating')}</p>
        </div>
      );
    }

    // Error from a previous attempt
    if (oidcAuth.error) {
      return (
        <div style={{ padding: '2rem', maxWidth: '480px', margin: '0 auto' }}>
          <Alert type={VariantType.ERROR}>{t('auth.failed', { error: oidcAuth.error })}</Alert>
          <div style={{ display: 'flex', justifyContent: 'center', marginTop: '1rem' }}>
            <Button onClick={oidcAuth.requestAuth}>{t('auth.retry')}</Button>
          </div>
        </div>
      );
    }

    // Auth needed — show explanation and "Continue" button
    if (oidcAuth.needsAuth) {
      return (
        <div style={{ padding: '2rem', maxWidth: '480px', margin: '0 auto' }}>
          <Alert type={VariantType.INFO}>{t('auth.required_explanation')}</Alert>
          <div style={{ display: 'flex', justifyContent: 'center', marginTop: '1.5rem' }}>
            <Button onClick={oidcAuth.requestAuth}>{t('auth.continue')}</Button>
          </div>
        </div>
      );
    }

    // Waiting for parentContext.suiteUserId — if token restore was already
    // attempted and we still have no userId, the parent didn't send auth context.
    if (tokenRestoreAttempted && !parentContext.suiteUserId) {
      return (
        <div style={{ padding: '2rem', maxWidth: '480px', margin: '0 auto' }}>
          <Alert type={VariantType.WARNING}>{t('auth.no_user_context')}</Alert>
        </div>
      );
    }

    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '200px' }}>
        <Loader />
      </div>
    );
  }

  switch (activeRoute) {
    case 'onboarding':
      return (
        <ModalEncryptionOnboarding
          getToken={getValidToken}
          userId={internalUserId}
          parentOrigin={parentContext.parentOrigin}
          hasExistingBackendKey={hasExistingBackendKey}
          existingKeyFingerprint={existingKeyFingerprint}
          userInfo={userInfo}
          onSuccess={handleOnboardingSuccess}
          onClose={handleClose}
          onUseAnotherDevice={() => setRouteOverride('device-approval')}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          currentAccessToken={oidcAuth.token}
        />
      );

    case 'backup':
      return (
        <ModalEncryptionOnboarding
          getToken={getValidToken}
          userId={internalUserId}
          parentOrigin={parentContext.parentOrigin}
          hasExistingBackendKey={true}
          existingKeyFingerprint={existingKeyFingerprint}
          userInfo={userInfo}
          onSuccess={handleOnboardingSuccess}
          onClose={handleClose}
          onUseAnotherDevice={() => setRouteOverride('device-approval')}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          currentAccessToken={oidcAuth.token}
        />
      );

    case 'restore':
      return (
        <ModalEncryptionOnboarding
          getToken={getValidToken}
          userId={internalUserId}
          parentOrigin={parentContext.parentOrigin}
          hasExistingBackendKey={true}
          existingKeyFingerprint={existingKeyFingerprint}
          userInfo={userInfo}
          onSuccess={handleOnboardingSuccess}
          onClose={handleClose}
          onUseAnotherDevice={() => setRouteOverride('device-approval')}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          currentAccessToken={oidcAuth.token}
        />
      );

    case 'settings':
      return (
        <EncryptionSettings
          userInfo={userInfo}
          userId={internalUserId}
          getToken={getValidToken}
          onClose={handleClose}
          onKeysDestroyed={() => notifyParent(parentContext.parentOrigin, MSG_INTERFACE_CLOSED)}
          onOpenDeviceApproval={() => setRouteOverride('device-approval')}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          currentAccessToken={oidcAuth.token}
        />
      );

    case 'device-approval':
      return (
        <DeviceApproval
          getToken={getValidToken}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          currentAccessToken={oidcAuth.token}
          onAdopted={() => {
            notifyParent(parentContext.parentOrigin, MSG_INTERFACE_ONBOARDING_COMPLETE, {});

            // Real navigation: the vault now has keys here, so the base route is
            // settings from now on (URL included, so a refresh stays put). The
            // approval overlay stays until the user dismisses its success screen.
            navigate('settings');
          }}
          onClose={routeOverride ? () => setRouteOverride(null) : handleClose}
        />
      );

    case 'verify-recipients':
      return (
        <VerifyRecipients
          recipients={parentContext.verifyRecipients ?? {}}
          onComplete={(outcome) => notifyParent(parentContext.parentOrigin, MSG_INTERFACE_VERIFY_COMPLETE, { outcome })}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          currentAccessToken={oidcAuth.token}
        />
      );

    case 'recipient-profile':
      return (
        <RecipientProfile
          userId={parentContext.recipientProfile?.userId ?? null}
          label={parentContext.recipientProfile?.label}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          currentAccessToken={oidcAuth.token}
        />
      );

    default:
      return null;
  }
}

// Browser version check — computed once at module load
const browserCheck = checkBrowserVersion();

export function App() {
  const { t, i18n } = useTranslation('common');
  const [route, setRoute] = useState<Route | null>(() => getRouteFromPath(window.location.pathname));
  const [cunninghamTheme, setCunninghamTheme] = useState<string>(getThemeFromHash);

  // In-app navigation: push the route's path (keeping the hash, which carries
  // theme/lang) so the URL reflects the screen and a refresh stays on it.
  const navigate = useCallback((to: Route) => {
    const path = PATH_FOR_ROUTE[to];

    if (path) window.history.pushState({}, '', path + window.location.hash);

    setRoute(to);
  }, []);

  // Apply language from hash: /onboarding#theme=dark&lang=en
  useEffect(() => {
    const lang = getLangFromHash();

    if (lang) {
      i18n.changeLanguage(lang);
    }
  }, [i18n]);

  useEffect(() => {
    const handleHashChange = () => {
      setCunninghamTheme(getThemeFromHash());

      const lang = getLangFromHash();

      if (lang) {
        i18n.changeLanguage(lang);
      }
    };

    window.addEventListener('hashchange', handleHashChange);

    // Live theme updates from the parent product (SDK setTheme). Driven via
    // postMessage rather than an iframe src/hash change so an internal
    // navigation (e.g. an unsaved recovery phrase mid-backup) is preserved.
    const handleThemeMessage = (event: MessageEvent) => {
      const data = event.data as { type?: string; theme?: string } | null;

      if (data?.type === MSG_INTERFACE_SET_THEME && typeof data.theme === 'string') {
        setCunninghamTheme(data.theme);
      }
    };

    window.addEventListener('message', handleThemeMessage);

    return () => {
      window.removeEventListener('hashchange', handleHashChange);
      window.removeEventListener('message', handleThemeMessage);
    };
  }, [i18n]);

  useEffect(() => {
    const handlePopState = () => setRoute(getRouteFromPath(window.location.pathname));

    window.addEventListener('popstate', handlePopState);

    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // OIDC auth routes — opened in a new tab, not inside an iframe
  if (route === 'login') {
    return (
      <CunninghamProvider theme={cunninghamTheme}>
        <LoginPage />
      </CunninghamProvider>
    );
  }

  if (route === 'auth-callback') {
    return (
      <CunninghamProvider theme={cunninghamTheme}>
        <CallbackPage />
      </CunninghamProvider>
    );
  }

  // Documentation routes
  if (route === 'docs-user' || route === 'docs-technical') {
    if (!DOCS_ENABLED) {
      return (
        <CunninghamProvider theme={cunninghamTheme}>
          <div
            style={{
              padding: 'var(--c--globals--spacings--8, 32px)',
              textAlign: 'center',
              color: 'var(--c--contextuals--content--surface--secondary, #666)',
            }}
          >
            <p>{t('docs.disabled')}</p>
          </div>
        </CunninghamProvider>
      );
    }

    return <CunninghamProvider theme={cunninghamTheme}>{route === 'docs-technical' ? <TechnicalDocsPage /> : <UserDocsPage />}</CunninghamProvider>;
  }

  // Encryption interface routes
  if (route) {
    return (
      <CunninghamProvider theme={cunninghamTheme}>
        {!browserCheck.supported && (
          <div
            role="alert"
            style={{
              padding: 'var(--c--globals--spacings--3, 12px)',
              borderLeft: '4px solid var(--c--globals--colors--error-500, #ce0500)',
              background: 'var(--c--contextuals--background--semantic--contextual--error, #ffe9e6)',
              borderRadius: '0 4px 4px 0',
              fontSize: 13,
              margin: 'var(--c--globals--spacings--3, 12px)',
            }}
          >
            {t('browser_warning.message', {
              browser: browserCheck.browser?.name ?? t('browser_warning.unknown'),
              version: browserCheck.browser?.version ?? '?',
              minVersion: browserCheck.minVersion ?? '?',
            })}
          </div>
        )}
        <EncryptionProvider>
          <InterfaceRoutes route={route} navigate={navigate} />
        </EncryptionProvider>
      </CunninghamProvider>
    );
  }

  return null;
}
