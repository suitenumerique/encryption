import { Alert, Button, Loader, Modal, ModalSize, VariantType } from '@gouvfr-lasuite/cunningham-react';
import type { TFunction } from 'i18next';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { formatFingerprint } from '@encryption/src/crypto/fingerprint';
import { mnemonicLanguageForLocale } from '@encryption/src/crypto/mnemonic';
import { MSG_VAULT_DESTROY_KEYS } from '@encryption/src/shared/constants';
import { API_ERROR_CONCURRENT_REGISTRATION, API_ERROR_KEY_VERSION_CONFLICT } from '@encryption/src/shared/error-codes';
import { VaultError, VaultErrorCode, isVaultError } from '@encryption/src/shared/vault-error';
import type { UserInfo } from '@encryption/src/ui/App';
import { ApiError, apiDefaults, authHeaders } from '@encryption/src/ui/api/client';
import {
  deleteApiPublicKeys,
  getApiPublicKeys,
  getApiPublicKeysNext,
  postApiPublicKeysRegisterInit,
  postApiVault,
} from '@encryption/src/ui/api/generated/sdk.gen';
import { SessionExpiredError, withFreshToken } from '@encryption/src/ui/auth/session-expired';
import { FingerprintDisplay } from '@encryption/src/ui/components/FingerprintDisplay';
import { RecoveryKitBackup } from '@encryption/src/ui/components/RecoveryKitBackup';
import { RecoveryPhraseInput } from '@encryption/src/ui/components/RecoveryPhraseInput';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
import { useSessionExpired } from '@encryption/src/ui/hooks/useSessionExpired';
import { useUnsavedPhraseGuard } from '@encryption/src/ui/hooks/useUnsavedPhraseGuard';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';
import type { OnboardingBundle } from '@encryption/src/vault/operations/onboarding';

type OnboardingStep =
  | 'checking-history'
  | 'explanation'
  | 'existing-key-choice'
  | 'previous-identity'
  | 'last-resort'
  | 'generating'
  | 'restore'
  | 'backup';

/**
 * "Start from scratch" confirmation step.
 * Requires the user to type their existing fingerprint before allowing deletion.
 */
function LastResortStep({
  existingKeyFingerprint,
  isPending,
  onConfirm,
  onBack,
  t,
}: {
  existingKeyFingerprint: string | null | undefined;
  isPending: boolean;
  onConfirm: () => void;
  onBack: () => void;
  t: TFunction;
}) {
  const [confirmInput, setConfirmInput] = useState('');
  const hasFingerprint = !!existingKeyFingerprint;
  const inputNormalized = confirmInput.toLowerCase().replace(/\s/g, '');
  const fingerprintMatch = hasFingerprint && inputNormalized === existingKeyFingerprint;
  const canDelete = hasFingerprint ? fingerprintMatch : true; // if no fingerprint available, allow (shouldn't happen)

  return (
    <>
      <h2>{t('onboarding.title_last_resort')}</h2>

      <Alert type={VariantType.ERROR}>{t('onboarding.last_resort_warning')}</Alert>

      <ul style={{ fontSize: 13, lineHeight: 1.6, margin: 'var(--c--globals--spacings--3, 12px) 0', paddingLeft: 20 }}>
        <li>{t('onboarding.last_resort_consequence_1')}</li>
        <li>{t('onboarding.last_resort_consequence_2')}</li>
        <li>{t('onboarding.last_resort_consequence_3')}</li>
      </ul>

      {hasFingerprint && (
        <div style={{ marginTop: 12, borderTop: '1px solid var(--c--contextuals--border--surface--primary, #ddd)', paddingTop: 12 }}>
          <p style={{ fontSize: 13, margin: '0 0 8px' }}>{t('onboarding.confirm_fingerprint_to_delete')}</p>
          <div
            style={{
              fontSize: 14,
              padding: 'var(--c--globals--spacings--2, 8px)',
              background: 'var(--c--contextuals--background--surface--secondary, #f5f5fe)',
              borderRadius: 4,
              marginBottom: 8,
            }}
          >
            <FingerprintDisplay fingerprint={existingKeyFingerprint!} style={{ fontSize: 14 }} />
          </div>
          <input
            type="text"
            value={confirmInput}
            onChange={(e) => setConfirmInput(e.target.value)}
            placeholder={formatFingerprint(existingKeyFingerprint!)}
            style={{
              width: '100%',
              boxSizing: 'border-box',
              fontFamily: 'monospace',
              fontSize: 14,
              letterSpacing: '0.05em',
              padding: 'var(--c--globals--spacings--2, 8px)',
              borderRadius: 4,
              border: `1px solid ${fingerprintMatch ? 'var(--c--globals--colors--success-500, #0d6635)' : 'var(--c--contextuals--border--surface--primary, #e5e5e5)'}`,
            }}
          />
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
        <Button variant="secondary" onClick={onBack}>
          {t('onboarding.btn_back')}
        </Button>
        <Button color="error" onClick={onConfirm} disabled={isPending || !canDelete}>
          {isPending ? t('onboarding.btn_generating') : t('onboarding.btn_confirm_reset')}
        </Button>
      </div>
    </>
  );
}

interface ModalEncryptionOnboardingProps {
  getToken: () => Promise<string | null>;
  userId: string | null;
  parentOrigin?: string | null;
  hasExistingBackendKey?: boolean;
  existingKeyFingerprint?: string | null;
  userInfo?: UserInfo | null;
  onSuccess?: (publicKey: string) => void;
  onClose: () => void;
  /** Navigate to the device-approval flow to receive keys from another device. */
  onUseAnotherDevice?: () => void;
  /**
   * Triggered when the user clicks "Reconnect" after a session-expired
   * error. Wire to `oidcAuth.requestAuth` — opens a new tab to /login.
   */
  onReconnect?: () => void;
  /** True while the re-auth tab is open and we're awaiting its result. */
  isAuthenticating?: boolean;
  /**
   * Current access token value. Used purely as a change detector: when
   * the token becomes a new string after the user has clicked Reconnect
   * we auto-clear the "session expired" banner. We can't rely on
   * `isAuthenticated` because `getValidToken` leaves `tokenSet` intact
   * on refresh failure (so the hook still reports authenticated even
   * when the token is already dead) — the identity of the access token
   * is the only reliable "actually refreshed" signal from the outside.
   */
  currentAccessToken?: string | null;
}

/**
 * Map a caught unlock error to its i18n key. Only WRONG_SECRET_KEY blames the
 * recovery phrase; a server-integrity failure gets its own message, and anything
 * else (network, 500, missing identity) falls back to the generic error rather
 * than being misattributed to a typo.
 */
function unlockErrorKey(
  err: unknown
): 'errors.vault.integrity_failed' | 'errors.vault.wrong_recovery_phrase' | 'errors.vault.no_vault_to_restore' | 'errors.unknown' {
  if (isVaultError(err)) {
    if (err.code === VaultErrorCode.VAULT_INTEGRITY_FAILED) return 'errors.vault.integrity_failed';
    if (err.code === VaultErrorCode.WRONG_SECRET_KEY) return 'errors.vault.wrong_recovery_phrase';
    if (err.code === VaultErrorCode.NOT_INITIALIZED) return 'errors.vault.no_vault_to_restore';
  }

  return 'errors.unknown';
}

export function ModalEncryptionOnboarding({
  getToken,
  userId,
  hasExistingBackendKey = false,
  parentOrigin = null,
  existingKeyFingerprint = null,
  userInfo = null,
  onSuccess,
  onClose,
  onUseAnotherDevice,
  onReconnect,
  isAuthenticating = false,
  currentAccessToken = null,
}: ModalEncryptionOnboardingProps) {
  const { t, i18n } = useTranslation('common');
  const {
    generateKeys,
    commitStagedVault,
    uncommitStagedVault,
    getPublicKey,
    request,
    respondToKeyChallenge,
    signKeyRegistration,
    prepareOnboarding,
    restoreFromPhrase,
    reactivateVault,
    syncVault,
  } = useEncryptionContext();

  // With an active server key -> existing-key-choice. Otherwise DON'T show the
  // fresh "Enable" screen yet: first check (checking-history) whether the account
  // has a disabled/dormant identity, so we never flash "Enable encryption" (and
  // let the user mint a NEW identity) when they actually have history to restore.
  const [step, setStep] = useState<OnboardingStep>(hasExistingBackendKey ? 'existing-key-choice' : 'checking-history');
  const [isPending, setIsPending] = useState(false);
  const [backupPassphrase, setBackupPassphrase] = useState<string | null>(null);
  // The locally-prepared onboarding bundle, held between the backup step and the
  // moment the user confirms the backup. NOTHING is sent to the server until then,
  // so abandoning the backup step leaves no server-side registration or vault.
  const [onboardingBundle, setOnboardingBundle] = useState<{ bundle: OnboardingBundle; version: number } | null>(null);
  const [isCommitting, setIsCommitting] = useState(false);
  const [commitError, setCommitError] = useState<string | null>(null);
  const [restoreInput, setRestoreInput] = useState('');
  // True only when every word box of the recovery phrase is filled; gates the restore button.
  const [restoreComplete, setRestoreComplete] = useState(false);
  // Set when the entered phrase unlocked a DORMANT vault: shows an in-app confirm
  // modal (not window.confirm) before reactivating, since that demotes the current one.
  const [reactivatePrompt, setReactivatePrompt] = useState<{ date: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { sessionExpired, markSessionExpired, clearSessionExpired } = useSessionExpired(currentAccessToken, isAuthenticating);
  // True when the user has just performed the "delete old key" flow.
  // Used to (a) skip the existing-key-choice auto-redirect below since
  // `hasExistingBackendKey` stays stale-true until the parent refetches,
  // and (b) show a one-line success banner on the fresh explanation
  // step so the user sees the deletion happened.
  const [hasJustReset, setHasJustReset] = useState(false);

  // Update the step when hasExistingBackendKey changes (e.g., context
  // message arrives after mount). Skip the redirect right after a reset —
  // the parent hasn't refetched yet so `hasExistingBackendKey` would
  // bounce the user back to the existing-key-choice step they just chose
  // to leave behind.
  useEffect(() => {
    if (hasExistingBackendKey && (step === 'explanation' || step === 'checking-history' || step === 'previous-identity') && !hasJustReset) {
      setStep('existing-key-choice');
    }
  }, [hasExistingBackendKey, step, hasJustReset]);

  // Resolve the checking-history step AUTHORITATIVELY from the server (the
  // `hasExistingBackendKey` prop arrives async and may still be a stale false):
  //   - an ACTIVE identity exists            -> existing-key-choice
  //   - no active but a DISABLED/dormant one -> previous-identity (restore/reactivate)
  //     (next_version > 1 means some key ever existed = there is history)
  //   - nothing at all                       -> explanation (truly new account)
  // Right after a reset we go straight to enable. On error we fail open to enable
  // so onboarding is never blocked. Runs once.
  const historyChecked = useRef(false);

  useEffect(() => {
    if (hasExistingBackendKey || step !== 'checking-history') return;

    if (hasJustReset) {
      setStep('explanation');

      return;
    }
    if (historyChecked.current || !userId) return;

    historyChecked.current = true;
    (async () => {
      try {
        const active = await getApiPublicKeys({ ...apiDefaults, query: { user_ids: [userId] } });

        if (active.data.keys.length > 0) {
          setStep('existing-key-choice');

          return;
        }

        const next = await withFreshToken(getToken, (token) => getApiPublicKeysNext({ ...apiDefaults, headers: authHeaders(token) }));
        setStep(next.data.next_version > 1 ? 'previous-identity' : 'explanation');
      } catch {
        setStep('explanation');
      }
    })();
  }, [hasExistingBackendKey, hasJustReset, step, getToken, userId]);

  // Build the onboarding bundle LOCALLY (recovery phrase + keyring + sealed items
  // + signed manifest) without touching the server. The only server call here is
  // reading the next version/generation. The actual registration + vault creation
  // is deferred to handleCommitOnboarding, which runs only after the user confirms
  // they saved the recovery phrase.
  const prepareOnboardingBundle = useCallback(async (): Promise<{ bundle: OnboardingBundle; version: number }> => {
    if (!userId) throw new Error(t('errors.vault.registration_failed'));

    const lang = mnemonicLanguageForLocale(i18n.language);

    return withFreshToken(getToken, async (token) => {
      // Count disabled rows too, so a re-onboard after a reset seals `max + 1`.
      const { data } = await getApiPublicKeysNext({ ...apiDefaults, headers: authHeaders(token) });
      const bundle = await prepareOnboarding({ lang, version: data.next_version, generation: data.next_generation });

      return { bundle, version: data.next_version };
    });
  }, [userId, getToken, i18n.language, prepareOnboarding, t]);

  // Commit the prepared onboarding to the server: prove possession of both keys
  // and create the synchronized vault in ONE atomic transaction (POST /api/vault).
  // Runs only from the backup step, after the user confirms the backup, so the
  // server never has a half-registered user with an unsaved recovery phrase.
  const handleCommitOnboarding = useCallback(async () => {
    if (!onboardingBundle || !userId) return;

    setIsCommitting(true);
    setCommitError(null);
    clearSessionExpired();

    // A registration for this user can land between prepare and this commit (e.g.
    // onboarding in another tab), making the version we signed stale. The server
    // rejects it with a 409; re-seal the keys at a fresh version and retry. The
    // recovery phrase is reused so the one the user already saved stays valid.
    const MAX_COMMIT_ATTEMPTS = 3;
    const isVersionConflict = (err: unknown) =>
      err instanceof ApiError && (err.code === API_ERROR_KEY_VERSION_CONFLICT || err.code === API_ERROR_CONCURRENT_REGISTRATION);

    try {
      let current = onboardingBundle;

      // Commit the staged vault to disk BEFORE talking to the server, so the
      // registration + first sync run against the real persisted vault (the sync's
      // read-modify-write and the server revision land on disk normally). If the
      // server round-trip fails, the catch below uncommits it.
      await commitStagedVault();

      for (let attempt = 0; ; attempt++) {
        try {
          await withFreshToken(getToken, async (token) => {
            const reg = await signKeyRegistration(current.version, Date.now());

            const init = await postApiPublicKeysRegisterInit({
              ...apiDefaults,
              headers: authHeaders(token),
              body: {
                user_id: userId,
                encryption_public_key: reg.encryptionPublicKey,
                signature_public_key: reg.signaturePublicKey,
                version: reg.version,
                created_at_millis: reg.createdAtMillis,
                key_binding_signature: reg.keyBindingSignature,
              },
            });
            const challengeId = init.data.challenge_id;
            const { response, challengeSignature } = await respondToKeyChallenge(challengeId, init.data.ciphertext);

            await postApiVault({
              ...apiDefaults,
              headers: authHeaders(token),
              body: {
                registration: { challenge_id: challengeId, response, challenge_signature: challengeSignature },
                keyring: current.bundle.keyring,
                items: current.bundle.items,
                manifest: current.bundle.manifest,
                manifest_sig: current.bundle.manifestSig,
              },
            });

            // Pull the just-bootstrapped vault so the local cache revision matches the
            // server. A transport error is best-effort (the next sync reconciles), but
            // an integrity-error means the server already served back tampered/incoherent
            // data for a vault we just wrote — surface it loudly rather than swallow it.
            const sync = await syncVault(token).catch(() => null);
            if (sync?.status === 'integrity-error')
              throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'Vault failed its integrity check right after creation.');
          });

          break;
        } catch (err) {
          if (attempt >= MAX_COMMIT_ATTEMPTS - 1 || !isVersionConflict(err)) throw err;

          // Re-seal at the now-current version, keeping the same phrase/keyring.
          const lang = mnemonicLanguageForLocale(i18n.language);
          const refreshed = await withFreshToken(getToken, async (token) => {
            const { data } = await getApiPublicKeysNext({ ...apiDefaults, headers: authHeaders(token) });
            const bundle = await prepareOnboarding({
              lang,
              version: data.next_version,
              generation: data.next_generation,
              reusePhrase: current.bundle.recoveryPhrase,
            });

            return { bundle, version: data.next_version };
          });

          current = refreshed;
          setOnboardingBundle(refreshed);
        }
      }

      // Registration + first sync succeeded: the vault is already committed on
      // disk (has-keys is now true), nothing more to persist.
      const { publicKey } = await getPublicKey();
      onSuccess?.(publicKey);
      onClose();
    } catch (err) {
      // The server round-trip failed after we committed locally: roll the vault
      // back out of IndexedDB so has-keys is false again (the user is not
      // registered), while it stays staged in memory for a retry with the same
      // phrase. Best-effort: a failed rollback must not mask the original error.
      await uncommitStagedVault().catch(() => {});

      if (err instanceof SessionExpiredError) {
        markSessionExpired();
      } else if (isVaultError(err) && err.code === VaultErrorCode.VAULT_INTEGRITY_FAILED) {
        setCommitError(t('errors.vault.integrity_failed'));
      } else {
        // The generic message is intentionally coarse for the user, but the real
        // cause (an API error code, a PoP failure, a transport error) must not be
        // swallowed silently: log it so a failing onboarding is diagnosable.
        console.error('[onboarding] vault bootstrap failed', err);
        setCommitError(t('errors.vault.registration_failed'));
      }
    } finally {
      setIsCommitting(false);
    }
  }, [
    onboardingBundle,
    userId,
    getToken,
    signKeyRegistration,
    respondToKeyChallenge,
    syncVault,
    commitStagedVault,
    uncommitStagedVault,
    getPublicKey,
    prepareOnboarding,
    i18n.language,
    onSuccess,
    onClose,
    markSessionExpired,
    clearSessionExpired,
    t,
  ]);

  // Back out of the backup step before committing: nothing is on the server yet,
  // but the local keys were minted, so destroy them to return to a clean state.
  const handleCancelBackup = useCallback(async () => {
    try {
      await request(MSG_VAULT_DESTROY_KEYS);
    } catch {
      // Best-effort cleanup
    }
    setOnboardingBundle(null);
    setBackupPassphrase(null);
    setCommitError(null);
    onClose();
  }, [request, onClose]);

  const handleGenerateKeys = useCallback(async () => {
    setIsPending(true);
    setError(null);
    clearSessionExpired();

    try {
      // Mint both key pairs (encryption + identity/signature) locally. They are
      // STAGED in memory only: nothing touches IndexedDB (so has-keys stays false)
      // until the backup is confirmed and the server registration succeeds.
      // Abandoning the flow here (reload, close) therefore leaves no keys behind.
      await generateKeys();

      // Build the recovery phrase + bundle LOCALLY. Nothing is registered on the
      // server yet: that happens only once the user confirms the backup. If the
      // local prepare fails, destroy the just-minted keys so we leave no residue.
      let prepared: { bundle: OnboardingBundle; version: number };

      try {
        prepared = await prepareOnboardingBundle();
      } catch (prepError) {
        try {
          await request(MSG_VAULT_DESTROY_KEYS);
        } catch {
          // Best effort cleanup
        }
        if (prepError instanceof SessionExpiredError) {
          throw prepError;
        }
        throw new Error(t('errors.vault.registration_failed'));
      }

      setOnboardingBundle(prepared);
      setBackupPassphrase(prepared.bundle.recoveryPhrase);
      setCommitError(null);
      setStep('backup');
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        markSessionExpired();
      } else {
        setError((err as Error).message);
      }
    } finally {
      setIsPending(false);
    }
  }, [generateKeys, prepareOnboardingBundle, request, t, markSessionExpired, clearSessionExpired]);

  const handleResetFromZero = useCallback(async () => {
    setIsPending(true);
    setError(null);
    clearSessionExpired();

    try {
      // Disable the existing public key on the server, then move the
      // user straight into the fresh-onboarding flow inside the same
      // modal. Previously we closed on success, which left the user
      // stranded with no confirmation and required them to re-open the
      // encryption modal to create new keys. `withFreshToken` turns a
      // failed OIDC refresh into a recoverable `SessionExpiredError`
      // surfaced via the Reconnect UI.
      await withFreshToken(getToken, (token) => deleteApiPublicKeys({ ...apiDefaults, headers: authHeaders(token) }));
      setHasJustReset(true);
      setStep('explanation');
      return;
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        markSessionExpired();
      } else {
        setError((err as Error).message);
      }
    } finally {
      setIsPending(false);
    }
  }, [getToken, markSessionExpired, clearSessionExpired]);

  const handleRestoreKeys = useCallback(async () => {
    if (!restoreComplete) return;

    setIsPending(true);
    setError(null);
    clearSessionExpired();

    const phrase = restoreInput.trim();

    try {
      // Cold-unlock the server vault with the recovery phrase: the phrase both
      // proves possession (PoP gate) and unwraps the VRK. No re-registration —
      // the keys were registered at the original onboarding.
      const { publicKey, isActiveVault, vaultCreatedAtMillis } = await withFreshToken(getToken, (token) => restoreFromPhrase(phrase, token));

      // If the phrase resolved to a DORMANT (superseded) vault, nothing has been
      // stored locally yet: bringing it back demotes the current vault, so we ask
      // first (in-app modal), then reactivation is what commits and caches. The
      // demoted vault stays recoverable with its own phrase.
      if (!isActiveVault) {
        setReactivatePrompt({ date: new Intl.DateTimeFormat(i18n.language).format(new Date(vaultCreatedAtMillis)) });

        return;
      }

      onSuccess?.(publicKey);
      onClose();
    } catch (err) {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else setError(t(unlockErrorKey(err)));
    } finally {
      setIsPending(false);
    }
  }, [restoreInput, restoreComplete, restoreFromPhrase, getToken, onSuccess, onClose, t, i18n.language, markSessionExpired, clearSessionExpired]);

  // Confirmed reactivation of the dormant vault the phrase unlocked.
  const handleConfirmReactivate = useCallback(async () => {
    setIsPending(true);
    setError(null);

    try {
      const reactivated = await withFreshToken(getToken, (token) => reactivateVault(restoreInput.trim(), token));
      setReactivatePrompt(null);
      onSuccess?.(reactivated.publicKey);
      onClose();
    } catch (err) {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else setError(t(unlockErrorKey(err)));
    } finally {
      setIsPending(false);
    }
  }, [getToken, reactivateVault, restoreInput, onSuccess, onClose, markSessionExpired, t]);

  // Warn on tab reload/close while the backup step shows an un-confirmed phrase.
  useUnsavedPhraseGuard(step === 'backup' && !isCommitting);

  return (
    <div style={{ padding: 'var(--c--globals--spacings--4, 16px)' }}>
      {sessionExpired && onReconnect && <SessionExpiredAlert onReconnect={onReconnect} isAuthenticating={isAuthenticating} />}
      {error && <Alert type={VariantType.ERROR}>{error}</Alert>}

      <Modal
        isOpen={reactivatePrompt !== null}
        onClose={isPending ? () => undefined : () => setReactivatePrompt(null)}
        closeOnClickOutside={false}
        size={ModalSize.MEDIUM}
        title={t('onboarding.reactivate_title')}
      >
        <p style={{ fontSize: 14 }}>{reactivatePrompt ? t('onboarding.reactivate_confirm', { date: reactivatePrompt.date }) : ''}</p>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
          <Button variant="secondary" onClick={() => setReactivatePrompt(null)} disabled={isPending}>
            {t('onboarding.btn_cancel')}
          </Button>
          <Button onClick={handleConfirmReactivate} disabled={isPending}>
            {isPending ? t('onboarding.btn_restoring') : t('onboarding.reactivate_confirm_button')}
          </Button>
        </div>
      </Modal>

      {step === 'checking-history' && (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 160 }}>
          <Loader />
        </div>
      )}

      {step === 'explanation' && (
        <>
          {hasJustReset && (
            <Alert type={VariantType.SUCCESS}>
              {t('onboarding.reset_success', 'Your previous keys have been disabled (not deleted). You can now set up new ones.')}
            </Alert>
          )}
          <h2>{t('onboarding.title_enable')}</h2>
          {userInfo?.name && (
            <p style={{ color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
              {userInfo.name}
              {userInfo.email ? ` (${userInfo.email})` : ''}
            </p>
          )}
          <p>{t('onboarding.explanation')}</p>
          <p>{t('onboarding.explanation_backup_prompt')}</p>
          <SecurityNotice t={t} />
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
            <Button variant="secondary" onClick={onClose}>
              {t('onboarding.btn_cancel')}
            </Button>
            <Button onClick={handleGenerateKeys} disabled={isPending}>
              {isPending ? t('onboarding.btn_generating') : t('onboarding.btn_enable')}
            </Button>
          </div>
        </>
      )}

      {step === 'existing-key-choice' && (
        <>
          <h2>{t('onboarding.title_existing')}</h2>
          {userInfo?.name && (
            <p style={{ color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
              {userInfo.name}
              {userInfo.email ? ` (${userInfo.email})` : ''}
            </p>
          )}

          <Alert type={VariantType.INFO}>{t('onboarding.existing_server_detected')}</Alert>

          {existingKeyFingerprint && (
            <div
              style={{
                padding: 'var(--c--globals--spacings--3, 12px)',
                background: 'var(--c--contextuals--background--surface--secondary, #f5f5fe)',
                borderRadius: 4,
                margin: 'var(--c--globals--spacings--3, 12px) 0',
              }}
            >
              <p style={{ fontSize: 13, fontWeight: 700, margin: '0 0 4px' }}>{t('settings.fingerprint_label')}</p>
              <div
                style={{
                  fontSize: 16,
                  padding: 'var(--c--globals--spacings--2, 8px)',
                  background: 'var(--c--contextuals--background--surface--primary, #fff)',
                  borderRadius: 4,
                }}
              >
                <FingerprintDisplay fingerprint={existingKeyFingerprint} style={{ fontSize: 16 }} />
              </div>
            </div>
          )}

          <p style={{ fontSize: 13, color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>{t('onboarding.existing_recovery_hint')}</p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 16 }}>
            <Button variant="secondary" fullWidth onClick={() => setStep('restore')}>
              {t('onboarding.btn_restore_from_backup')}
            </Button>
            {onUseAnotherDevice && (
              <Button variant="secondary" fullWidth onClick={onUseAnotherDevice}>
                {t('onboarding.btn_use_another_device')}
              </Button>
            )}
            <Button variant="tertiary" fullWidth onClick={() => setStep('last-resort')}>
              {t('onboarding.btn_last_resort')}
            </Button>
            <Button variant="tertiary" fullWidth onClick={onClose}>
              {t('onboarding.btn_cancel')}
            </Button>
          </div>
        </>
      )}

      {step === 'previous-identity' && (
        <>
          <h2>{t('onboarding.title_previous_identity')}</h2>
          {userInfo?.name && (
            <p style={{ color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
              {userInfo.name}
              {userInfo.email ? ` (${userInfo.email})` : ''}
            </p>
          )}
          <Alert type={VariantType.INFO}>{t('onboarding.previous_identity_detected')}</Alert>
          <p style={{ fontSize: 13, color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>{t('onboarding.previous_identity_hint')}</p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 16 }}>
            <Button fullWidth onClick={() => setStep('restore')}>
              {t('onboarding.btn_restore_from_backup')}
            </Button>
            {onUseAnotherDevice && (
              <Button variant="secondary" fullWidth onClick={onUseAnotherDevice}>
                {t('onboarding.btn_use_another_device')}
              </Button>
            )}
            <Button variant="tertiary" fullWidth onClick={() => setStep('explanation')}>
              {t('onboarding.btn_start_new_identity')}
            </Button>
            <Button variant="tertiary" fullWidth onClick={onClose}>
              {t('onboarding.btn_cancel')}
            </Button>
          </div>
        </>
      )}

      {step === 'last-resort' && (
        <LastResortStep
          existingKeyFingerprint={existingKeyFingerprint}
          isPending={isPending}
          onConfirm={handleResetFromZero}
          onBack={() => setStep('existing-key-choice')}
          t={t}
        />
      )}

      {step === 'generating' && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
          <Loader />
          <p>{t('onboarding.title_generating')}</p>
        </div>
      )}

      {step === 'restore' && (
        <>
          <h2>{t('onboarding.title_restore')}</h2>
          <SecurityNotice t={t} />
          <p style={{ fontSize: 13, margin: '8px 0' }}>{t('onboarding.restore_placeholder')}</p>
          <RecoveryPhraseInput
            onChange={(phrase, complete) => {
              setRestoreInput(phrase);
              setRestoreComplete(complete);
            }}
          />
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
            <Button
              variant="secondary"
              onClick={() => {
                setError(null);
                setRestoreInput('');
                setRestoreComplete(false);
                // Return to wherever restore was entered from: the active-key
                // choice, the previous-identity choice (disabled/dormant history),
                // or the bare enable screen.
                setStep(hasExistingBackendKey ? 'existing-key-choice' : historyChecked.current ? 'previous-identity' : 'explanation');
              }}
            >
              {t('onboarding.btn_back')}
            </Button>
            <Button onClick={handleRestoreKeys} disabled={isPending || !restoreComplete}>
              {isPending ? t('onboarding.btn_restoring') : t('onboarding.btn_restore')}
            </Button>
          </div>
        </>
      )}

      {step === 'backup' && backupPassphrase && (
        <>
          <h2>{t('onboarding.title_backup')}</h2>
          <Alert type={VariantType.INFO}>{t('onboarding.backup_success')}</Alert>
          <RecoveryKitBackup
            passphrase={backupPassphrase}
            parentOrigin={parentOrigin}
            onConfirm={handleCommitOnboarding}
            confirmLabel={t('onboarding.btn_backup_done')}
            busyLabel={t('onboarding.finalizing')}
            isBusy={isCommitting}
            error={commitError}
            onCancel={handleCancelBackup}
            cancelLabel={t('onboarding.btn_cancel')}
          />
        </>
      )}
    </div>
  );
}

/**
 * Security notice about browser extensions.
 * Shown during onboarding and key restoration to remind users
 * that browser extensions can potentially access page content.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function SecurityNotice({ t }: { t: TFunction }) {
  return (
    <div style={{ marginTop: 'var(--c--globals--spacings--3, 12px)', marginBottom: 'var(--c--globals--spacings--3, 12px)' }}>
      <Alert type={VariantType.INFO}>{t('onboarding.extensions_warning')}</Alert>
    </div>
  );
}
