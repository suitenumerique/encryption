import { Button, CunninghamProvider, Modal, ModalSize, VariantType } from '@gouvfr-lasuite/ui-components';
import { type ReactNode, Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  MSG_INTERFACE_CLOSED,
  MSG_INTERFACE_ONBOARDING_COMPLETE,
  MSG_INTERFACE_SET_THEME,
  MSG_INTERFACE_SHOWN,
  MSG_INTERFACE_VERIFY_COMPLETE,
} from '@encryption/src/shared/constants';
import { fetchPublicKeys } from '@encryption/src/ui/api/public-keys-client';
import { CallbackPage } from '@encryption/src/ui/auth/CallbackPage';
import { LoginPage } from '@encryption/src/ui/auth/LoginPage';
import { clearIdTokenSet, readIdTokenSet, storeIdTokenSet, subscribeToIdTokenSet } from '@encryption/src/ui/auth/id-token-storage';
import { isIdTokenExpired } from '@encryption/src/ui/auth/login';
import { checkBrowserVersion } from '@encryption/src/ui/browser-check';
import { CouncilCustodian } from '@encryption/src/ui/components/CouncilCustodian';
import { DeviceApproval } from '@encryption/src/ui/components/DeviceApproval';
import { EmergencyAccess } from '@encryption/src/ui/components/EmergencyAccess';
import { EmergencySignedOutPrompt } from '@encryption/src/ui/components/EmergencySignedOutPrompt';
import { EncryptionSettings } from '@encryption/src/ui/components/EncryptionSettings';
import { ModalEncryptionOnboarding } from '@encryption/src/ui/components/ModalEncryptionOnboarding';
import { RecipientProfile } from '@encryption/src/ui/components/RecipientProfile';
import { RecoveryCouncil } from '@encryption/src/ui/components/RecoveryCouncil';
import { VerifyRecipients } from '@encryption/src/ui/components/VerifyRecipients';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import { CloseRequestProvider } from '@encryption/src/ui/hooks/useCloseRequest';
import { ModalSizeProvider } from '@encryption/src/ui/hooks/useModalSize';
import { useOidcAuth } from '@encryption/src/ui/hooks/useOidcAuth';
import { type ParentContext, useParentMessages } from '@encryption/src/ui/hooks/useParentMessages';
import { EncryptionProvider, useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';
import { PATH_FOR_ROUTE, type Route, getRouteFromPath, getSettingsSectionFromPath } from '@encryption/src/ui/routes';
import { runtimeConfig } from '@encryption/src/ui/runtime-config';
import { resolveThemeName } from '@encryption/src/ui/theme';

const DOCS_ENABLED = runtimeConfig.docsEnabled ?? true;

// The documentation (MDX pages, syntax highlighting) is its own chunk: no modal
// a product opens should download it.
const TechnicalDocsPage = lazy(() => import('@encryption/src/ui/docs/TechnicalDocsPage').then((m) => ({ default: m.TechnicalDocsPage })));
const UserDocsPage = lazy(() => import('@encryption/src/ui/docs/UserDocsPage').then((m) => ({ default: m.UserDocsPage })));

function getHashParams(): URLSearchParams {
  return new URLSearchParams(window.location.hash.slice(1));
}

/**
 * The design system theme from the URL hash: the parent passes it as
 * /onboarding#theme=dsfr. Default: "default" (white label light theme).
 */
function getThemeFromHash(): string {
  return resolveThemeName(getHashParams().get('theme'));
}

/** The design system's built-in strings (alert controls, form helpers) follow the interface language. */
function designSystemLocale(language: string): string {
  return language.startsWith('fr') ? 'fr-FR' : 'en-US';
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

/**
 * Owns the parent handshake and answers the product's close requests. The
 * product's own close control never unmounts the iframe by itself: it asks, the
 * screen shown may object (an unsaved recovery phrase), and the interface
 * confirms with MSG_INTERFACE_CLOSED once it is really done. Wrapping every
 * state here (auth gates included) guarantees a request is always answered.
 */
function InterfaceRoutes({ route, navigate }: { route: Route; navigate: (to: Route) => void }) {
  const { t } = useTranslation('common');
  const parentContext = useParentMessages();
  // A screen opened from another one (settings -> emergency access, onboarding
  // -> device approval) replaces it without changing the URL; lives here so the
  // modal around the screens can follow the one actually shown.
  const [routeOverride, setRouteOverride] = useState<Route | null>(null);
  const activeRoute = routeOverride ?? route;
  // The interface's own modal is closed like the product's used to be: a close
  // request, which the shown screen may hold (an unsaved recovery phrase).
  const [ownCloseRequests, setOwnCloseRequests] = useState(0);
  const requestClose = useCallback(() => setOwnCloseRequests((n) => n + 1), []);

  // The SDK keeps the frame invisible until this report, so the frame gets no
  // animation frame before it and cannot wait for a paint: the report follows
  // the first commit, by which time the modal and its backdrop are in the DOM
  // (the design system opens its modal in that same commit), and the SDK shows
  // the frame and has the product drop its loader together.
  useEffect(() => {
    if (window.parent === window) return;

    window.parent.postMessage({ type: MSG_INTERFACE_SHOWN }, '*');
  }, []);
  const handleClose = useCallback(() => {
    notifyParent(parentContext.parentOrigin, MSG_INTERFACE_CLOSED);
  }, [parentContext.parentOrigin]);

  // The SDK lays a transparent full-viewport iframe over the product; the modal
  // the user sees (backdrop, card, close control, width) is drawn HERE, so no
  // size ever crosses the two windows. Documentation pages are whole pages, and
  // two screens draw a modal of their own: the verify overlay, and the emergency
  // prompt the SDK opens on its own (told apart by the context it carries).
  // A screen asks for the wide modal itself (useModalSize), so the width follows
  // the step actually shown, the sign-in gates included.
  const fullPage = route === 'docs-user' || route === 'docs-technical';
  const drawsOwnModal = route === 'verify-recipients' || (activeRoute === 'emergency-access' && parentContext.emergencyPending !== null);

  // The two screens drawing their own modal do so only once shown: in their place,
  // those screens still need one, or they sprawl see-through.
  const frameGate = (screen: ReactNode): ReactNode =>
    drawsOwnModal ? (
      <Modal isOpen onClose={requestClose} closeOnClickOutside={false} size={ModalSize.SMALL} aria-label={t('interface.title')}>
        {screen}
      </Modal>
    ) : (
      screen
    );

  const screens = (
    <InterfaceScreens
      route={route}
      navigate={navigate}
      parentContext={parentContext}
      routeOverride={routeOverride}
      setRouteOverride={setRouteOverride}
      frameGate={frameGate}
    />
  );

  return (
    <CloseRequestProvider requests={parentContext.closeRequests + ownCloseRequests} onClose={handleClose}>
      {fullPage || drawsOwnModal ? (
        screens
      ) : (
        <ModalSizeProvider>
          {(size) => (
            <Modal
              isOpen
              onClose={requestClose}
              closeOnClickOutside={false}
              size={size === 'large' ? ModalSize.LARGE : size === 'medium' ? ModalSize.MEDIUM : ModalSize.SMALL}
              aria-label={t('interface.title')}
            >
              {screens}
            </Modal>
          )}
        </ModalSizeProvider>
      )}
    </CloseRequestProvider>
  );
}

/** Inner component that has access to the EncryptionContext */
function InterfaceScreens({
  route,
  navigate,
  parentContext,
  routeOverride,
  setRouteOverride,
  frameGate,
}: {
  route: Route;
  navigate: (to: Route) => void;
  parentContext: ParentContext;
  routeOverride: Route | null;
  setRouteOverride: (to: Route | null) => void;
  frameGate: (screen: ReactNode) => ReactNode;
}) {
  const { t } = useTranslation('common');
  const { setAuthInfo, hasKeys, isReady, resolveInternalUser } = useEncryptionContext();

  // The INTERNAL encryption user id. Resolved vault-first (alias store /
  // registry, no ID token needed, so settings work with an expired one), with
  // the user id the server returned at sign-in as the fallback for a never-onboarded user. It is what the
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

  // OIDC self-authentication: the interface obtains its own ID token.
  const oidcAuth = useOidcAuth(parentContext.suiteUserId);
  // Both are stable across renders (a state setter and a memoized callback), so
  // depending on them directly keeps the effects below honest about what they
  // use without re-running them on every render — which listing the whole
  // `oidcAuth` object would do.
  const { updateIdTokenSet, clearIdTokenSet: dropIdTokenSet } = oidcAuth;

  // Restore the ID token from the interface's own localStorage (not the vault).
  // This avoids re-authentication when the iframe is recreated (page refresh, modal close/open).
  const [restoreAttemptedFor, setRestoreAttemptedFor] = useState<string | null>(null);
  const tokenRestoreAttempted = restoreAttemptedFor !== null;

  if (parentContext.suiteUserId && !oidcAuth.idToken && restoreAttemptedFor !== parentContext.suiteUserId) {
    setRestoreAttemptedFor(parentContext.suiteUserId);

    const stored = readIdTokenSet(parentContext.suiteUserId);

    if (stored && stored.sub === parentContext.suiteUserId && !isIdTokenExpired(stored)) {
      updateIdTokenSet(stored);
    }
  }

  // Adopt the ID token another page signed in with (another product tab, or a
  // step-up there), so its sign-in screen does not wait for a click of its own.
  useEffect(() => {
    if (!parentContext.suiteUserId) return;

    const suiteUserId = parentContext.suiteUserId;

    return subscribeToIdTokenSet(suiteUserId, (stored) => {
      if (stored.sub === suiteUserId && !isIdTokenExpired(stored)) {
        updateIdTokenSet(stored);
      }
    });
  }, [parentContext.suiteUserId, updateIdTokenSet]);

  // If the parent never completes the auth-context handshake (suiteUserId never
  // arrives), the token-restore effect above never runs, so tokenRestoreAttempted
  // stays false and the "no user context" warning below would be unreachable —
  // the UI would spin forever. A bounded wait flips this flag so that state
  // resolves to the warning instead of an endless loader. Cleared automatically
  // if the context arrives first (effect cleanup on the dep change).
  const [handshakeTimedOut, setHandshakeTimedOut] = useState(false);

  useEffect(() => {
    if (parentContext.suiteUserId || oidcAuth.idToken) return;

    const timer = setTimeout(() => setHandshakeTimedOut(true), 10000);

    return () => clearTimeout(timer);
  }, [parentContext.suiteUserId, oidcAuth.idToken]);

  // Persist the ID token in localStorage once signed in.
  useEffect(() => {
    if (!oidcAuth.idTokenSet || !parentContext.suiteUserId) return;

    storeIdTokenSet(parentContext.suiteUserId, oidcAuth.idTokenSet);
  }, [oidcAuth.idTokenSet, parentContext.suiteUserId]);

  // A usable ID token, or null once it expired. There is no refresh: past its
  // expiry it is dropped from memory AND localStorage, so `needsAuth` flips back
  // on and the user is offered to sign in again (a tab that closes by itself
  // while the provider's own session is alive).
  const getValidIdToken = useCallback(async (): Promise<string | null> => {
    const idTokenSet = oidcAuth.idTokenSet;

    if (!idTokenSet) return null;

    if (isIdTokenExpired(idTokenSet)) {
      if (parentContext.suiteUserId) {
        clearIdTokenSet(parentContext.suiteUserId);
      }

      dropIdTokenSet();

      return null;
    }

    return idTokenSet.idToken;
  }, [oidcAuth.idTokenSet, parentContext.suiteUserId, dropIdTokenSet]);

  // Components get the ID token for display/checks, but must call
  // getValidIdToken() before actual API calls, which drops an expired one.
  const signedInUserId = oidcAuth.idTokenSet?.userId ?? null;

  // Resolve the internal user id, vault first: the alias/registry chain needs
  // no ID token, so an onboarded user gets their id (and a working settings
  // page) even with an expired one. The sign-in answer is the fallback for a
  // never-onboarded user: the server minted the user row when it signed them in
  // (the row must exist before onboarding can sign a key registration, since the
  // internal id is inside the binding signature) and answered with its id.
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
        // Vault unavailable: fall through to the sign-in answer below.
      }

      // No ID token at all: NOT a stuck state — the render falls to the
      // sign-in branch, which shows a reconnect action rather than a spinner.
      if (!cancelled && signedInUserId) setInternalUserId(signedInUserId);
    })();

    return () => {
      cancelled = true;
    };
  }, [isReady, signedInUserId, internalUserId, resolveInternalUser]);

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

  // Lets a screen (e.g. settings) push into device-approval in place without a
  // real navigation, then return to where it was.
  const activeRoute = routeOverride ?? route;
  const settingsSection = route === 'settings' ? getSettingsSectionFromPath(window.location.pathname) : null;

  // Who the ID token is for, as the provider described them at sign-in.
  const userInfo = useMemo<UserInfo | null>(
    () =>
      oidcAuth.idTokenSet
        ? { name: [oidcAuth.idTokenSet.firstName, oidcAuth.idTokenSet.lastName].filter(Boolean).join(' '), email: oidcAuth.idTokenSet.email }
        : null,
    [oidcAuth.idTokenSet]
  );

  // Check for existing backend keys, to route the user to restore instead of
  // fresh onboarding. Queried by sub because that is the only id the parent
  // context guarantees, through the unauthenticated directory form, so it
  // works with no (or an expired) ID token, like resolution above.
  useEffect(() => {
    if (!parentContext.suiteUserId) return;

    // Directory lookup by OIDC sub (unauthenticated, like every directory read):
    // used before the internal id is resolved.
    fetchPublicKeys({ subs: [parentContext.suiteUserId] })
      .then((data) => setHasExistingBackendKey(data.keys.length > 0))
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
  // Show a loader while trying to restore a token from the vault.
  // This prevents a flash of the "Authentication required" screen.
  if (!oidcAuth.idToken && !tokenRestoreAttempted && !handshakeTimedOut) {
    return frameGate(<LoadingScreen />);
  }

  // Wait for OIDC authentication.
  if (!oidcAuth.idToken) {
    // Waiting for the sign-in tab. No deadline, and no "the tab was closed": the
    // iframe cannot see the tab once a provider page cut the link, so the user
    // decides, by opening the sign-in again or cancelling.
    // Back from the sign-in tab: its result is being fetched, nothing to reopen.
    if (oidcAuth.isAuthenticating && oidcAuth.isConfirming) {
      return frameGate(<LoadingScreen label={t('auth.confirming')} />);
    }

    if (oidcAuth.isAuthenticating) {
      return frameGate(
        <Screen
          illustration="shield-gear"
          title={t('auth.required_title')}
          description={t('auth.authenticating')}
          actions={
            <>
              <Button onClick={oidcAuth.requestAuth}>{t('auth.reopen')}</Button>
              <Button variant="bordered" color="neutral" onClick={oidcAuth.cancelAuth}>
                {t('auth.cancel')}
              </Button>
            </>
          }
        />
      );
    }

    // Error from a previous attempt
    if (oidcAuth.error) {
      return frameGate(
        <Screen
          title={t('auth.required_title')}
          banner={
            oidcAuth.wrongUser ? (
              <Notice type={VariantType.WARNING}>{oidcAuth.error}</Notice>
            ) : (
              <Notice type={VariantType.ERROR}>{t('auth.failed', { error: oidcAuth.error })}</Notice>
            )
          }
          actions={<Button onClick={oidcAuth.requestAuth}>{oidcAuth.wrongUser ? t('auth.sign_in_another_account') : t('auth.retry')}</Button>}
        />
      );
    }

    // Auth needed — show explanation and "Continue" button
    if (oidcAuth.needsAuth) {
      // The emergency prompt the SDK opened on its own: say what is pending at once.
      const emergencyPending = activeRoute === 'emergency-access' ? parentContext.emergencyPending : null;
      if (emergencyPending?.recovery || emergencyPending?.invitation) {
        return frameGate(<EmergencySignedOutPrompt recovery={emergencyPending.recovery} onSignIn={oidcAuth.requestAuth} />);
      }

      return frameGate(
        <Screen
          illustration="shield-gear"
          title={t('auth.required_title')}
          description={t('auth.required_explanation')}
          actions={<Button onClick={oidcAuth.requestAuth}>{t('auth.continue')}</Button>}
        />
      );
    }

    // No auth context from the parent: either the token-restore ran (context was
    // briefly present) or the handshake timed out without it ever arriving. Either
    // way, show the warning rather than spin — the interface cannot proceed
    // without knowing which user is authenticated.
    if ((tokenRestoreAttempted || handshakeTimedOut) && !parentContext.suiteUserId) {
      return frameGate(<Screen banner={<Notice type={VariantType.WARNING}>{t('auth.no_user_context')}</Notice>} />);
    }

    return frameGate(<LoadingScreen />);
  }

  // Opened over another screen (settings home, onboarding), a flow comes back to
  // it; opened on its own (its route, or a product's settings section), it closes
  // the interface when done.
  const overlaid = routeOverride !== null;

  function emergencyAccess(direct: boolean) {
    return (
      <EmergencyAccess
        getIdToken={getValidIdToken}
        onBack={overlaid && !direct ? () => setRouteOverride(null) : undefined}
        onClose={overlaid && !direct ? () => setRouteOverride(null) : handleClose}
        onReconnect={oidcAuth.requestAuth}
        isAuthenticating={oidcAuth.isAuthenticating}
        onCancelAuth={oidcAuth.cancelAuth}
        currentIdToken={oidcAuth.idToken}
        emergencyPending={parentContext.emergencyPending}
      />
    );
  }

  // The council screens ask for a fresh second factor on custodian actions.
  const councilAuth = {
    onReconnect: oidcAuth.requestAuth,
    onStepUp: oidcAuth.requestStepUp,
    isAuthenticating: oidcAuth.isAuthenticating,
    onCancelAuth: oidcAuth.cancelAuth,
    currentIdToken: oidcAuth.idToken,
  };

  function recoveryCouncil(direct: boolean) {
    return (
      <RecoveryCouncil
        {...councilAuth}
        getIdToken={getValidIdToken}
        onBack={overlaid && !direct ? () => setRouteOverride(null) : undefined}
        onClose={overlaid && !direct ? () => setRouteOverride(null) : handleClose}
      />
    );
  }

  function councilCustodian(direct: boolean) {
    return (
      <CouncilCustodian
        {...councilAuth}
        getIdToken={getValidIdToken}
        userId={internalUserId}
        onBack={overlaid && !direct ? () => setRouteOverride(null) : undefined}
        onClose={overlaid && !direct ? () => setRouteOverride(null) : handleClose}
      />
    );
  }

  function deviceApproval(direct: boolean) {
    return (
      <DeviceApproval
        getIdToken={getValidIdToken}
        onReconnect={oidcAuth.requestAuth}
        isAuthenticating={oidcAuth.isAuthenticating}
        onCancelAuth={oidcAuth.cancelAuth}
        currentIdToken={oidcAuth.idToken}
        onAdopted={() => {
          notifyParent(parentContext.parentOrigin, MSG_INTERFACE_ONBOARDING_COMPLETE, {});

          // Real navigation: the vault now has keys here, so the base route is
          // settings from now on (URL included, so a refresh stays put). The
          // approval overlay stays until the user dismisses its success screen.
          if (!direct) navigate('settings');
        }}
        onBack={overlaid && !direct ? () => setRouteOverride(null) : undefined}
        onClose={overlaid && !direct ? () => setRouteOverride(null) : handleClose}
      />
    );
  }

  switch (activeRoute) {
    case 'onboarding':
      return (
        <ModalEncryptionOnboarding
          getIdToken={getValidIdToken}
          userId={internalUserId}
          parentOrigin={parentContext.parentOrigin}
          hasExistingBackendKey={hasExistingBackendKey}
          userInfo={userInfo}
          onSuccess={handleOnboardingSuccess}
          onClose={handleClose}
          onUseAnotherDevice={() => setRouteOverride('device-approval')}
          onOpenEmergencyAccess={() => navigate('emergency-access')}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          onCancelAuth={oidcAuth.cancelAuth}
          currentIdToken={oidcAuth.idToken}
          currentIdTokenSet={oidcAuth.idTokenSet}
          onStepUp={oidcAuth.requestStepUp}
        />
      );

    case 'backup':
      return (
        <ModalEncryptionOnboarding
          getIdToken={getValidIdToken}
          userId={internalUserId}
          parentOrigin={parentContext.parentOrigin}
          hasExistingBackendKey={true}
          userInfo={userInfo}
          onSuccess={handleOnboardingSuccess}
          onClose={handleClose}
          onUseAnotherDevice={() => setRouteOverride('device-approval')}
          onOpenEmergencyAccess={() => navigate('emergency-access')}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          onCancelAuth={oidcAuth.cancelAuth}
          currentIdToken={oidcAuth.idToken}
          currentIdTokenSet={oidcAuth.idTokenSet}
          onStepUp={oidcAuth.requestStepUp}
        />
      );

    case 'restore':
      return (
        <ModalEncryptionOnboarding
          getIdToken={getValidIdToken}
          userId={internalUserId}
          parentOrigin={parentContext.parentOrigin}
          hasExistingBackendKey={true}
          userInfo={userInfo}
          onSuccess={handleOnboardingSuccess}
          onClose={handleClose}
          onUseAnotherDevice={() => setRouteOverride('device-approval')}
          onOpenEmergencyAccess={() => navigate('emergency-access')}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          onCancelAuth={oidcAuth.cancelAuth}
          currentIdToken={oidcAuth.idToken}
          currentIdTokenSet={oidcAuth.idTokenSet}
          onStepUp={oidcAuth.requestStepUp}
        />
      );

    case 'settings': {
      // A product's account page opens one flow at a time; the trusted contacts and
      // the device pairing are screens of their own, the rest belongs to settings.
      if (settingsSection === 'add-device') return deviceApproval(true);
      if (settingsSection === 'trusted-contacts') return emergencyAccess(true);
      if (settingsSection === 'recovery-council') return recoveryCouncil(true);
      if (settingsSection === 'custodian') return councilCustodian(true);

      return (
        <EncryptionSettings
          userInfo={userInfo}
          userId={internalUserId}
          getIdToken={getValidIdToken}
          section={settingsSection}
          onClose={handleClose}
          onKeysDestroyed={() => notifyParent(parentContext.parentOrigin, MSG_INTERFACE_CLOSED)}
          onSetUp={() => navigate('onboarding')}
          onOpenDeviceApproval={() => setRouteOverride('device-approval')}
          onOpenEmergencyAccess={() => setRouteOverride('emergency-access')}
          onOpenRecoveryCouncil={() => setRouteOverride('recovery-council')}
          onOpenCustodian={() => setRouteOverride('council-custodian')}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          onCancelAuth={oidcAuth.cancelAuth}
          currentIdToken={oidcAuth.idToken}
        />
      );
    }

    case 'emergency-access':
      return emergencyAccess(false);

    case 'recovery-council':
      return recoveryCouncil(false);

    case 'council-custodian':
      return councilCustodian(false);

    case 'device-approval':
      return deviceApproval(false);

    case 'verify-recipients':
      return (
        <VerifyRecipients
          recipients={parentContext.verifyRecipients ?? {}}
          onComplete={(outcome) => notifyParent(parentContext.parentOrigin, MSG_INTERFACE_VERIFY_COMPLETE, { outcome })}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          onCancelAuth={oidcAuth.cancelAuth}
          currentIdToken={oidcAuth.idToken}
        />
      );

    case 'recipient-profile':
      return (
        <RecipientProfile
          userId={parentContext.recipientProfile?.userId ?? null}
          label={parentContext.recipientProfile?.label ?? { email: '' }}
          onReconnect={oidcAuth.requestAuth}
          isAuthenticating={oidcAuth.isAuthenticating}
          onCancelAuth={oidcAuth.cancelAuth}
          currentIdToken={oidcAuth.idToken}
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
        setCunninghamTheme(resolveThemeName(data.theme));
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
      <CunninghamProvider theme={cunninghamTheme} currentLocale={designSystemLocale(i18n.language)}>
        <LoginPage />
      </CunninghamProvider>
    );
  }

  if (route === 'auth-callback') {
    return (
      <CunninghamProvider theme={cunninghamTheme} currentLocale={designSystemLocale(i18n.language)}>
        <CallbackPage />
      </CunninghamProvider>
    );
  }

  // Documentation routes
  if (route === 'docs-user' || route === 'docs-technical') {
    if (!DOCS_ENABLED) {
      return (
        <CunninghamProvider theme={cunninghamTheme} currentLocale={designSystemLocale(i18n.language)}>
          <Screen padded description={t('docs.disabled')} />
        </CunninghamProvider>
      );
    }

    return (
      <CunninghamProvider theme={cunninghamTheme} currentLocale={designSystemLocale(i18n.language)}>
        <Suspense fallback={<LoadingScreen />}>{route === 'docs-technical' ? <TechnicalDocsPage /> : <UserDocsPage />}</Suspense>
      </CunninghamProvider>
    );
  }

  // Encryption interface routes
  if (route) {
    return (
      <CunninghamProvider theme={cunninghamTheme} currentLocale={designSystemLocale(i18n.language)}>
        {!browserCheck.supported && (
          <div
            role="alert"
            style={{
              padding: 'var(--c--globals--spacings--sm)',
              border: '1px solid var(--c--contextuals--border--semantic--error--tertiary)',
              background: 'var(--c--contextuals--background--semantic--error--tertiary)',
              color: 'var(--c--contextuals--content--semantic--error--secondary)',
              borderRadius: 'var(--c--globals--spacings--xxxs)',
              fontSize: 'var(--c--globals--font--sizes--xs)',
              margin: 'var(--c--globals--spacings--sm)',
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
