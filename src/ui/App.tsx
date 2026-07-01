import { Alert, Button, CunninghamProvider, Loader, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import { MSG_INTERFACE_CLOSED, MSG_INTERFACE_ONBOARDING_COMPLETE } from '@encryption/src/shared/constants';
import { fetchPublicKeys } from '@encryption/src/ui/api/server-client';
import { CallbackPage } from '@encryption/src/ui/auth/CallbackPage';
import { LoginPage } from '@encryption/src/ui/auth/LoginPage';
import { checkBrowserVersion } from '@encryption/src/ui/browser-check';
import { DeviceTransfer } from '@encryption/src/ui/components/DeviceTransfer';
import { EncryptionSettings } from '@encryption/src/ui/components/EncryptionSettings';
import { ModalEncryptionOnboarding } from '@encryption/src/ui/components/ModalEncryptionOnboarding';
import { TechnicalDocsPage } from '@encryption/src/ui/docs/TechnicalDocsPage';
import { UserDocsPage } from '@encryption/src/ui/docs/UserDocsPage';
import { type TokenSet, refreshTokenWithLock, tokenNeedsRefresh } from '@encryption/src/ui/auth/oidc-client';
import { readToken, storeToken } from '@encryption/src/ui/auth/token-storage';
import { useOidcAuth } from '@encryption/src/ui/hooks/useOidcAuth';
import { useParentMessages } from '@encryption/src/ui/hooks/useParentMessages';
import { EncryptionProvider, useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

const runtimeAppConfig = (window as unknown as { __ENCRYPTION_CONFIG__?: { docsEnabled?: boolean } }).__ENCRYPTION_CONFIG__;
const DOCS_ENABLED = runtimeAppConfig?.docsEnabled ?? true;

type Route = 'onboarding' | 'backup' | 'restore' | 'device-transfer' | 'settings' | 'docs-user' | 'docs-technical' | 'login' | 'auth-callback';

function getRouteFromPath(path: string): Route | null {
  const routes: Record<string, Route> = {
    '/onboarding': 'onboarding',
    '/backup': 'backup',
    '/restore': 'restore',
    '/device-transfer': 'device-transfer',
    '/settings': 'settings',
    '/docs': 'docs-user',
    '/docs/user': 'docs-user',
    '/docs/technical': 'docs-technical',
    '/login': 'login',
    '/auth/callback': 'auth-callback',
  };

  return routes[path] ?? null;
}

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
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));

    return {
      name: payload.name || payload.preferred_username || null,
      email: payload.email || null,
    };
  } catch {
    return { name: null, email: null };
  }
}

/** Inner component that has access to the EncryptionContext */
function InterfaceRoutes({ route }: { route: Route }) {
  const parentContext = useParentMessages();
  const { t } = useTranslation('common');
  const { prepareTransferExport, claimTransferImport, setAuthInfo, request, isReady: vaultReady } = useEncryptionContext();

  // Set auth info on the encryption context FIRST — the vault needs this before
  // we can make any requests (including token restoration).
  useEffect(() => {
    if (parentContext.suiteUserId) {
      setAuthInfo(parentContext.suiteUserId);
    }
  }, [parentContext.suiteUserId, setAuthInfo]);

  // OIDC self-authentication: the interface obtains its own token.
  const oidcAuth = useOidcAuth(parentContext.suiteUserId);

  // Restore token from interface's own localStorage (not the vault).
  // This avoids re-authentication when the iframe is recreated (page refresh, modal close/open).
  const [tokenRestoreAttempted, setTokenRestoreAttempted] = useState(false);

  useEffect(() => {
    if (!parentContext.suiteUserId || oidcAuth.token) return;

    const stored = readToken(parentContext.suiteUserId);

    if (stored && stored.sub === parentContext.suiteUserId) {
      oidcAuth.updateTokenSet(stored);
    }

    setTokenRestoreAttempted(true);
  }, [parentContext.suiteUserId, oidcAuth.token]);

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

      const refreshed = await refreshTokenWithLock(currentTokenSet, readStoredToken);
      oidcAuth.updateTokenSet(refreshed);

      return refreshed.accessToken;
    } catch {
      // Refresh failed — token is expired and unrecoverable
      return null;
    }
  }, [oidcAuth.tokenSet, parentContext.suiteUserId]);

  // OIDC token for server API calls. Components use oidcToken for display/checks,
  // but must call getValidToken() before actual API calls to ensure the token
  // is fresh (lazy refresh with Web Locks mutex if it expires within 1 minute).
  const oidcToken = oidcAuth.token;


  const [hasExistingBackendKey, setHasExistingBackendKey] = useState(false);
  const [existingKeyFingerprint, setExistingKeyFingerprint] = useState<string | null>(null);
  const [routeOverride, setRouteOverride] = useState<Route | null>(null);
  const [deviceTransferMode, setDeviceTransferMode] = useState<'choose' | 'import' | 'export'>('choose');
  const activeRoute = routeOverride ?? route;

  const userInfo = useMemo<UserInfo | null>(() => {
    if (!oidcToken) return null;

    return decodeJwtUserInfo(oidcToken);
  }, [oidcToken]);

  // Check for existing backend keys once we have a userId
  useEffect(() => {
    if (!parentContext.suiteUserId) return;

    fetchPublicKeys([parentContext.suiteUserId])
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

  const { i18n } = useTranslation('common');

  const handleExportPayload = useCallback(async (): Promise<{ encryptedPayload: string; transferPassphrase: string }> => {
    // Pass the current i18n language so the mnemonic is generated in the user's language
    const mnemonicLanguage = i18n.language === 'en' ? 'english' : 'french';

    return prepareTransferExport(mnemonicLanguage as 'french' | 'english');
  }, [prepareTransferExport, i18n.language]);

  const handleImportPayload = useCallback(
    async (encryptedPayload: string, transferPassphrase: string): Promise<void> => {
      const { publicKey } = await claimTransferImport(encryptedPayload, transferPassphrase);

      // Notify parent that keys are available (updates hasKeys, publicKey state)
      // but do NOT close the interface — let the DeviceTransfer component show
      // its success screen. The user will click "Back" to close.
      notifyParent(parentContext.parentOrigin, MSG_INTERFACE_ONBOARDING_COMPLETE, { publicKey });
    },
    [claimTransferImport, parentContext.parentOrigin]
  );

  // All hooks declared above — conditional returns are safe below this point.
  // OIDC must be configured for the interface to work.
  if (!oidcAuth.isConfigured) {
    return <div style={{ padding: '2rem', maxWidth: '480px', margin: '0 auto' }}>
      <Alert type={VariantType.ERROR}>{t('auth.oidc_not_configured')}</Alert>
    </div>;
  }

  // Show a loader while trying to restore a token from the vault.
  // This prevents a flash of the "Authentication required" screen.
  if (!oidcAuth.token && !tokenRestoreAttempted) {
    return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '200px' }}>
      <Loader />
    </div>;
  }

  // Wait for OIDC authentication.
  if (!oidcAuth.token) {
    // Waiting for the login tab to complete
    if (oidcAuth.isAuthenticating) {
      return <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', minHeight: '200px', gap: '1rem', padding: '2rem' }}>
        <Loader />
        <p style={{ textAlign: 'center', margin: 0 }}>{t('auth.authenticating')}</p>
      </div>;
    }

    // Error from a previous attempt
    if (oidcAuth.error) {
      return <div style={{ padding: '2rem', maxWidth: '480px', margin: '0 auto' }}>
        <Alert type={VariantType.ERROR}>{t('auth.failed', { error: oidcAuth.error })}</Alert>
        <div style={{ display: 'flex', justifyContent: 'center', marginTop: '1rem' }}>
          <Button onClick={oidcAuth.requestAuth}>{t('auth.retry')}</Button>
        </div>
      </div>;
    }

    // Auth needed — show explanation and "Continue" button
    if (oidcAuth.needsAuth) {
      return <div style={{ padding: '2rem', maxWidth: '480px', margin: '0 auto' }}>
        <Alert type={VariantType.INFO}>{t('auth.required_explanation')}</Alert>
        <div style={{ display: 'flex', justifyContent: 'center', marginTop: '1.5rem' }}>
          <Button onClick={oidcAuth.requestAuth}>{t('auth.continue')}</Button>
        </div>
      </div>;
    }

    // Waiting for parentContext.suiteUserId — if token restore was already
    // attempted and we still have no userId, the parent didn't send auth context.
    if (tokenRestoreAttempted && !parentContext.suiteUserId) {
      return <div style={{ padding: '2rem', maxWidth: '480px', margin: '0 auto' }}>
        <Alert type={VariantType.WARNING}>{t('auth.no_user_context')}</Alert>
      </div>;
    }

    return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '200px' }}>
      <Loader />
    </div>;
  }

  switch (activeRoute) {
    case 'onboarding':
      return (
        <ModalEncryptionOnboarding
          getToken={getValidToken}
          userId={parentContext.suiteUserId}
          parentOrigin={parentContext.parentOrigin}
          hasExistingBackendKey={hasExistingBackendKey}
          existingKeyFingerprint={existingKeyFingerprint}
          userInfo={userInfo}
          onSuccess={handleOnboardingSuccess}
          onClose={handleClose}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          currentAccessToken={oidcAuth.token}
          onOpenDeviceTransfer={
            hasExistingBackendKey
              ? () => {
                  setDeviceTransferMode('import');
                  setRouteOverride('device-transfer');
                }
              : undefined
          }
        />
      );

    case 'backup':
      return (
        <ModalEncryptionOnboarding
          getToken={getValidToken}
          userId={parentContext.suiteUserId}
          parentOrigin={parentContext.parentOrigin}
          hasExistingBackendKey={true}
          existingKeyFingerprint={existingKeyFingerprint}
          userInfo={userInfo}
          onSuccess={handleOnboardingSuccess}
          onClose={handleClose}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          currentAccessToken={oidcAuth.token}
        />
      );

    case 'restore':
      return (
        <ModalEncryptionOnboarding
          getToken={getValidToken}
          userId={parentContext.suiteUserId}
          parentOrigin={parentContext.parentOrigin}
          hasExistingBackendKey={true}
          existingKeyFingerprint={existingKeyFingerprint}
          userInfo={userInfo}
          onSuccess={handleOnboardingSuccess}
          onClose={handleClose}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          currentAccessToken={oidcAuth.token}
        />
      );

    case 'device-transfer':
      return (
        <DeviceTransfer
          getToken={getValidToken}
          initialMode={routeOverride ? deviceTransferMode : 'choose'}
          onExportPayload={handleExportPayload}
          onImportPayload={handleImportPayload}
          onClose={
            routeOverride
              ? () => {
                  setRouteOverride(null);
                  setDeviceTransferMode('choose');
                }
              : handleClose
          }
        />
      );

    case 'settings':
      return (
        <EncryptionSettings
          userInfo={userInfo}
          getToken={getValidToken}
          onClose={handleClose}
          onKeysDestroyed={() => notifyParent(parentContext.parentOrigin, MSG_INTERFACE_CLOSED)}
          onOpenDeviceTransferExport={() => {
            setDeviceTransferMode('export');
            setRouteOverride('device-transfer');
          }}
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

    return () => window.removeEventListener('hashchange', handleHashChange);
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
          <InterfaceRoutes route={route} />
        </EncryptionProvider>
      </CunninghamProvider>
    );
  }

  return null;
}
