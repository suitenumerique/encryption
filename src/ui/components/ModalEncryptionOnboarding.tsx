import { Button, Checkbox, Modal, ModalSize, VariantType } from '@gouvfr-lasuite/ui-components';
import { Key, PhoneDesktop, ShieldCheck } from '@gouvfr-lasuite/ui-components/icons';
import type { TFunction } from 'i18next';
import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';

import { mnemonicLanguageForLocale } from '@encryption/src/crypto/mnemonic';
import { MSG_VAULT_DESTROY_KEYS } from '@encryption/src/shared/constants';
import { API_ERROR_CONCURRENT_REGISTRATION, API_ERROR_KEY_VERSION_CONFLICT } from '@encryption/src/shared/error-codes';
import type { VaultKeyringWire } from '@encryption/src/shared/schemas/vault';
import { VaultError, VaultErrorCode, isVaultError } from '@encryption/src/shared/vault-error';
import type { UserInfo } from '@encryption/src/ui/App';
import { ApiError } from '@encryption/src/ui/api/client';
import { fetchCouncilForMe } from '@encryption/src/ui/api/council-client';
import { fetchTrustedContacts } from '@encryption/src/ui/api/emergency-client';
import { deletePublicKeys, fetchNextKeyVersion, fetchPublicKeys, registerKeyInit } from '@encryption/src/ui/api/public-keys-client';
import { createVault, hasRestorableVault } from '@encryption/src/ui/api/vault-client';
import type { IdTokenSet } from '@encryption/src/ui/auth/login';
import { SessionExpiredError, StepUpRequiredError, withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { CouncilRecovery, type CouncilRecoveryResult } from '@encryption/src/ui/components/CouncilRecovery';
import { RecoveryKitBackup } from '@encryption/src/ui/components/RecoveryKitBackup';
import { RecoveryPhraseInput } from '@encryption/src/ui/components/RecoveryPhraseInput';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
import { StepUpScreen } from '@encryption/src/ui/components/StepUpScreen';
import { type BlockedContact, UntrustedRearmError, granteeName, personNameWithEmail } from '@encryption/src/ui/components/emergency-access-logic';
import { Identity } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { useCloseGuard } from '@encryption/src/ui/hooks/useCloseRequest';
import { useCouncilVault } from '@encryption/src/ui/hooks/useCouncilVault';
import { useKeyringCommit } from '@encryption/src/ui/hooks/useKeyringCommit';
import { useSessionExpired } from '@encryption/src/ui/hooks/useSessionExpired';
import { useStepUp } from '@encryption/src/ui/hooks/useStepUp';
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
  | 'restored'
  | 'backup'
  | 'done'
  | 'council-recovery'
  | 'forced-rotation'
  | 'forced-rotation-done';

/**
 * "Reset encryption" confirmation step, laid out like the design's turn-off
 * confirmation: the user acknowledges the data loss before the old key is disabled.
 */
function LastResortStep({
  isPending,
  onConfirm,
  onBack,
  banner,
  t,
}: {
  isPending: boolean;
  onConfirm: () => void;
  onBack: () => void;
  banner?: ReactNode;
  t: TFunction;
}) {
  // The "I understand" tick is the only confirmation, as when turning encryption off.
  const [understood, setUnderstood] = useState(false);

  return (
    <Screen
      back={{ label: t('onboarding.btn_back'), onClick: onBack, disabled: isPending }}
      title={t('onboarding.title_last_resort')}
      description={
        <>
          <p>{t('onboarding.last_resort_warning')}</p>
          <ul className={styles.list}>
            <li>{t('onboarding.last_resort_consequence_1')}</li>
            <li>{t('onboarding.last_resort_consequence_2')}</li>
            <li>{t('onboarding.last_resort_consequence_3')}</li>
          </ul>
        </>
      }
      banner={banner}
      actionsLayout="row"
      actions={
        <>
          <Button variant="bordered" color="neutral" onClick={onBack} disabled={isPending}>
            {t('onboarding.btn_cancel')}
          </Button>
          <Button color="error" onClick={onConfirm} disabled={isPending || !understood}>
            {isPending ? t('onboarding.btn_generating') : t('onboarding.btn_confirm_reset')}
          </Button>
        </>
      }
    >
      <Notice type={VariantType.ERROR}>
        <div className={styles.alertStack}>
          <span>{t('onboarding.last_resort_alert')}</span>
          <Checkbox label={t('onboarding.i_understand')} checked={understood} onChange={() => setUnderstood((v) => !v)} />
        </div>
      </Notice>
    </Screen>
  );
}

interface ModalEncryptionOnboardingProps {
  getIdToken: () => Promise<string | null>;
  userId: string | null;
  parentOrigin?: string | null;
  hasExistingBackendKey?: boolean;
  /** Accepted for parity with the settings screen; the onboarding screens do not show it. */
  userInfo?: UserInfo | null;
  onSuccess?: (publicKey: string) => void;
  onClose: () => void;
  /** Navigate to the device-approval flow to receive keys from another device. */
  onUseAnotherDevice?: () => void;
  /** Open the emergency-access screen (adoption nudge on the final success step). */
  onOpenEmergencyAccess?: () => void;
  /**
   * Triggered when the user clicks "Reconnect" after a session-expired
   * error. Wire to `oidcAuth.requestAuth` — opens a new tab to /login.
   */
  onReconnect?: () => void;
  /** True while the re-auth tab is open and we're awaiting its result. */
  isAuthenticating?: boolean;
  /** Stops waiting for that tab (`oidcAuth.cancelAuth`). */
  onCancelAuth?: () => void;
  /**
   * Current ID token value. Used purely as a change detector: when
   * the token becomes a new string after the user has clicked Reconnect
   * we auto-clear the "session expired" banner. We can't rely on
   * `isAuthenticated` because an ID token the server rejected stays in
   * place until the new one arrives (so the hook still reports
   * authenticated) — the identity of the token is the only reliable
   * "actually signed in again" signal from the outside.
   */
  currentIdToken?: string | null;
  /**
   * The current ID token with what the provider reported about the sign-in:
   * after a step-up, whether it carried a second factor.
   */
  currentIdTokenSet?: IdTokenSet | null;
  /**
   * Triggered when the user confirms their identity after the server asked for
   * a step-up (replacing an identity). Wire to `oidcAuth.requestStepUp`.
   */
  onStepUp: () => void;
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
  getIdToken,
  userId,
  hasExistingBackendKey = false,
  parentOrigin = null,
  onSuccess,
  onClose,
  onUseAnotherDevice,
  onOpenEmergencyAccess,
  onReconnect,
  isAuthenticating = false,
  onCancelAuth,
  currentIdToken = null,
  currentIdTokenSet = null,
  onStepUp,
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
    changeRecoveryPhrase,
    hasKeys,
  } = useEncryptionContext();

  // Set when this browser held the vault but forgot it after a long inactivity,
  // so asking to enroll again is explained rather than looking like a bug.
  const [deEnrolledAfterDays, setDeEnrolledAfterDays] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;

    hasKeys()
      .then(({ deEnrolled }) => {
        if (!cancelled && deEnrolled) setDeEnrolledAfterDays(deEnrolled.inactivityDays);
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
  }, [hasKeys]);

  // With an active server key -> existing-key-choice. Otherwise DON'T show the
  // fresh "Enable" screen yet: first check (checking-history) whether the account
  // has a disabled/dormant identity, so we never flash "Enable encryption" (and
  // let the user mint a NEW identity) when they actually have history to restore.
  const [step, setStep] = useState<OnboardingStep>(hasExistingBackendKey ? 'existing-key-choice' : 'checking-history');
  const [isPending, setIsPending] = useState(false);
  const [backupPassphrase, setBackupPassphrase] = useState<string | null>(null);
  // The phrase the user last confirmed as saved: if the backup screen comes back
  // (after a step-up, or a failed commit), it need not be saved again.
  const [confirmedPassphrase, setConfirmedPassphrase] = useState<string | null>(null);
  // The locally-prepared onboarding bundle, held between the backup step and the
  // moment the user confirms the backup. NOTHING is sent to the server until then,
  // so abandoning the backup step leaves no server-side registration or vault.
  const [onboardingBundle, setOnboardingBundle] = useState<{ bundle: OnboardingBundle; version: number } | null>(null);
  const [isCommitting, setIsCommitting] = useState(false);
  const [commitError, setCommitError] = useState<string | null>(null);
  const [restoreInput, setRestoreInput] = useState('');
  // The way back chosen on the "Restore your encryption" screen.
  const [restoreMethod, setRestoreMethod] = useState<'device' | 'phrase' | 'council'>(onUseAnotherDevice ? 'device' : 'phrase');
  // The user's council can give the vault back (an escrow enough custodians can
  // still open): one more way back, and the rotation after it re-arms the council.
  const [councilAvailable, setCouncilAvailable] = useState(false);
  const [councilUnlock, setCouncilUnlock] = useState(false);
  const [councilDropped, setCouncilDropped] = useState(false);
  const councilVault = useCouncilVault();

  useEffect(() => {
    let cancelled = false;

    getIdToken()
      .then((idToken) => (idToken ? fetchCouncilForMe(idToken) : null))
      .then((forMe) => {
        if (!cancelled && forMe?.escrow && forMe.escrow.health.status !== 'lost') setCouncilAvailable(true);
      })
      .catch(() => {
        // Optional way back: without an answer it is simply not offered.
      });

    return () => {
      cancelled = true;
    };
  }, [getIdToken]);
  // The entered phrase opened nothing: the boxes turn red until it is edited.
  const [phraseRejected, setPhraseRejected] = useState(false);
  // True only when every word box of the recovery phrase is filled; gates the restore button.
  const [restoreComplete, setRestoreComplete] = useState(false);
  // Set when the entered phrase unlocked a DORMANT vault: shows an in-app confirm
  // modal (not window.confirm) before reactivating, since that demotes the current one.
  const [reactivatePrompt, setReactivatePrompt] = useState<{ date: string; council?: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The "cancel the setup?" prompt raised by the product's close control on the backup step.
  const [cancelPrompt, setCancelPrompt] = useState(false);
  const { sessionExpired, markSessionExpired, clearSessionExpired } = useSessionExpired(currentIdToken, isAuthenticating);
  // Replacing an existing identity needs a fresh second-factor sign-in (step-up).
  // Once confirmed, the interrupted commit runs again (see the ref below).
  const retryAfterStepUpRef = useRef<() => void>(() => {});
  const retryAfterStepUp = useCallback(() => retryAfterStepUpRef.current(), []);
  const { stepUpState, markStepUpRequired, clearStepUp } = useStepUp(currentIdTokenSet, isAuthenticating, retryAfterStepUp);
  // MANDATORY phrase rotation after an emergency unlock: the phrase just used
  // was an escrowed one the trusted contact has seen, so it is burned by
  // design. The vault is already unlocked/adopted at this point; the new
  // keyring is held locally and committed (with the required emergency
  // re-arms) only once the user confirms the new phrase is saved.
  const [forcedRotation, setForcedRotation] = useState<{ recoveryPhrase: string; keyring: VaultKeyringWire; publicKey: string } | null>(null);
  const [rotationBusy, setRotationBusy] = useState(false);
  const [rotationError, setRotationError] = useState<string | null>(null);
  const [rotationBlocked, setRotationBlocked] = useState<BlockedContact[] | null>(null);
  const { commitKeyring, findBlockedContacts, revokeContacts } = useKeyringCommit(getIdToken);
  // The key the rotation reports once done, kept while a blocked contact holds it back.
  const [rotationPublicKey, setRotationPublicKey] = useState<string | null>(null);

  // True when the user has just performed the "delete old key" flow.
  // Used to (a) skip the existing-key-choice auto-redirect below since
  // `hasExistingBackendKey` stays stale-true until the parent refetches,
  // and (b) show a one-line success banner on the fresh explanation
  // step so the user sees the deletion happened.
  const [hasJustReset, setHasJustReset] = useState(false);

  // Update the step when hasExistingBackendKey changes (e.g., context message
  // arrives after mount). Skip the redirect right after a reset — the parent hasn't
  // refetched yet so `hasExistingBackendKey` would bounce the user back to the
  // existing-key-choice step they just chose to leave behind.
  if (hasExistingBackendKey && (step === 'explanation' || step === 'checking-history' || step === 'previous-identity') && !hasJustReset) {
    setStep('existing-key-choice');
  }

  // Right after a reset there is nothing to look up: go straight to enable.
  if (!hasExistingBackendKey && step === 'checking-history' && hasJustReset) {
    setStep('explanation');
  }

  // Resolve the checking-history step AUTHORITATIVELY from the server (the
  // `hasExistingBackendKey` prop arrives async and may still be a stale false):
  //   - an ACTIVE identity exists            -> existing-key-choice
  //   - no active but a DORMANT vault        -> previous-identity (restore/reactivate)
  //   - no vault left                        -> explanation (a new account, or one
  //     whose dormant vaults were all deleted by the retention job: no phrase can
  //     restore anything, so offering to would lead nowhere)
  // Right after a reset we go straight to enable. On error we fail open to enable
  // so onboarding is never blocked. Runs once.
  const historyChecked = useRef(false);
  // Trusted contacts who accepted their designation before the identity was
  // disabled: their escrow still opens that vault, so they can hand the phrase
  // back. Best effort, only worth a sentence when there is at least one.
  const [helpfulContacts, setHelpfulContacts] = useState<Array<{ id: string; name: string; email: string }>>([]);

  useEffect(() => {
    if (hasExistingBackendKey || step !== 'checking-history') return;

    // The reset case is handled above, while rendering.
    // Not done in the `useEffect` to have `useState` outside as expected by eslint
    if (hasJustReset || historyChecked.current || !userId) return;

    historyChecked.current = true;
    (async () => {
      try {
        const active = await fetchPublicKeys({ user_ids: [userId] });

        if (active.keys.length > 0) {
          setStep('existing-key-choice');

          return;
        }

        if (!(await withFreshIdToken(getIdToken, (idToken) => hasRestorableVault(idToken)))) {
          setStep('explanation');

          return;
        }

        setStep('previous-identity');
        try {
          const { contacts } = await withFreshIdToken(getIdToken, (idToken) => fetchTrustedContacts(idToken));
          setHelpfulContacts(
            contacts
              .filter((contact) => contact.status !== 'invited')
              .map((contact) => ({ id: contact.id, name: granteeName(contact), email: contact.grantee_email }))
          );
        } catch {
          // The hint is a courtesy: without the list the screen still offers every way in.
        }
      } catch {
        setStep('explanation');
      }
    })();
  }, [hasExistingBackendKey, hasJustReset, step, getIdToken, userId]);

  // Build the onboarding bundle LOCALLY (recovery phrase + keyring + sealed items
  // + signed manifest) without touching the server. The only server call here is
  // reading the next version/generation. The actual registration + vault creation
  // is deferred to handleCommitOnboarding, which runs only after the user confirms
  // they saved the recovery phrase.
  const prepareOnboardingBundle = useCallback(async (): Promise<{ bundle: OnboardingBundle; version: number }> => {
    if (!userId) throw new Error(t('errors.vault.registration_failed'));

    const lang = mnemonicLanguageForLocale(i18n.language);

    return withFreshIdToken(getIdToken, async (idToken) => {
      // Count disabled rows too, so a re-onboard after a reset seals `max + 1`.
      const data = await fetchNextKeyVersion(idToken);
      const bundle = await prepareOnboarding({ lang, version: data.next_version, generation: data.next_generation });

      return { bundle, version: data.next_version };
    });
  }, [userId, getIdToken, i18n.language, prepareOnboarding, t]);

  // Commit the prepared onboarding to the server: prove possession of both keys
  // and create the synchronized vault in ONE atomic transaction (POST /api/vault).
  // Runs only from the backup step, after the user confirms the backup, so the
  // server never has a half-registered user with an unsaved recovery phrase.
  const handleCommitOnboarding = useCallback(async () => {
    if (!onboardingBundle || !userId) return;

    setIsCommitting(true);
    setCommitError(null);
    clearSessionExpired();
    clearStepUp();

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
          await withFreshIdToken(getIdToken, async (idToken) => {
            const reg = await signKeyRegistration(current.version, Date.now());

            const init = await registerKeyInit(idToken, {
              user_id: userId,
              encryption_public_key: reg.encryptionPublicKey,
              signature_public_key: reg.signaturePublicKey,
              version: reg.version,
              created_at_millis: reg.createdAtMillis,
              key_binding_signature: reg.keyBindingSignature,
            });
            const challengeId = init.challenge_id;
            const { response, challengeSignature } = await respondToKeyChallenge(challengeId, init.ciphertext);

            await createVault(idToken, {
              registration: { challenge_id: challengeId, response, challenge_signature: challengeSignature },
              keyring: current.bundle.keyring,
              items: current.bundle.items,
              manifest: current.bundle.manifest,
              manifest_sig: current.bundle.manifestSig,
            });

            // Pull the just-bootstrapped vault so the local cache revision matches the
            // server. A transport error is best-effort (the next sync reconciles), but
            // an integrity-error means the server already served back tampered/incoherent
            // data for a vault we just wrote — surface it loudly rather than swallow it.
            const sync = await syncVault(idToken).catch(() => null);
            if (sync?.status === 'integrity-error')
              throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'Vault failed its integrity check right after creation.');
          });

          break;
        } catch (err) {
          if (attempt >= MAX_COMMIT_ATTEMPTS - 1 || !isVersionConflict(err)) throw err;

          // Re-seal at the now-current version, keeping the same phrase/keyring.
          const lang = mnemonicLanguageForLocale(i18n.language);
          const refreshed = await withFreshIdToken(getIdToken, async (idToken) => {
            const data = await fetchNextKeyVersion(idToken);
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
      // disk (has-keys is now true), nothing more to persist. A short success
      // screen follows (with the trusted-contact suggestion) instead of an
      // immediate close.
      const { publicKey } = await getPublicKey();
      onSuccess?.(publicKey);
      setStep('done');
    } catch (err) {
      // The server round-trip failed after we committed locally: roll the vault
      // back out of IndexedDB so has-keys is false again (the user is not
      // registered), while it stays staged in memory for a retry with the same
      // phrase. Best-effort: a failed rollback must not mask the original error.
      await uncommitStagedVault().catch(() => {});

      if (err instanceof SessionExpiredError) {
        markSessionExpired();
      } else if (err instanceof StepUpRequiredError) {
        // The account already has an identity: the server wants a fresh
        // second-factor sign-in before replacing it. The staged vault stays in
        // memory, so the commit is simply run again once it is confirmed.
        markStepUpRequired();
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
    getIdToken,
    signKeyRegistration,
    respondToKeyChallenge,
    syncVault,
    commitStagedVault,
    uncommitStagedVault,
    getPublicKey,
    prepareOnboarding,
    i18n.language,
    onSuccess,
    markSessionExpired,
    clearSessionExpired,
    markStepUpRequired,
    clearStepUp,
    t,
  ]);

  // The step-up came back with a second factor: finish what it interrupted.
  useEffect(() => {
    retryAfterStepUpRef.current = () => void handleCommitOnboarding();
  }, [handleCommitOnboarding]);

  // Back out of the backup step before committing: nothing is on the server yet,
  // but the local keys were minted, so destroy them to return to a clean state.
  // The screen goes back to the start as well: the product closes the interface
  // on `onClose`, but until it does (or where it does not, as in a story) the
  // flow must not sit on an empty backup step behind an open prompt.
  const handleCancelBackup = useCallback(async () => {
    try {
      await request(MSG_VAULT_DESTROY_KEYS);
    } catch {
      // Best-effort cleanup
    }
    setCancelPrompt(false);
    setOnboardingBundle(null);
    setBackupPassphrase(null);
    setCommitError(null);
    setStep('explanation');
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
        throw new Error(t('errors.vault.registration_failed'), { cause: prepError });
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
      // encryption modal to create new keys. `withFreshIdToken` turns a
      // missing or expired ID token into a recoverable `SessionExpiredError`
      // surfaced via the Reconnect UI.
      await withFreshIdToken(getIdToken, (idToken) => deletePublicKeys(idToken));
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
  }, [getIdToken, markSessionExpired, clearSessionExpired]);

  // Enter the mandatory post-emergency-unlock rotation: derive a fresh phrase +
  // keyring locally (nothing sent yet) and take over the whole view. The user
  // cannot skip it: the contact has seen the phrase that just unlocked the vault.
  // A granted contact who would block the commit is dealt with first, so the
  // phrase shown is one that can take effect.
  const startForcedRotation = useCallback(
    async (publicKey: string) => {
      setRotationPublicKey(publicKey);
      setRotationError(null);
      setRotationBlocked(null);

      let blocked: BlockedContact[] = [];
      try {
        blocked = await findBlockedContacts();
      } catch {
        // The vault is already restored: an unanswered check must not undo that,
        // and the commit enforces the same condition anyway.
      }

      if (blocked.length > 0) {
        setForcedRotation(null);
        setRotationBlocked(blocked);
        setStep('forced-rotation');

        return;
      }

      const lang = mnemonicLanguageForLocale(i18n.language);
      const { recoveryPhrase, keyring } = await changeRecoveryPhrase(lang);

      setForcedRotation({ recoveryPhrase, keyring, publicKey });
      setStep('forced-rotation');
    },
    [findBlockedContacts, changeRecoveryPhrase, i18n.language]
  );

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
      const { publicKey, isActiveVault, vaultCreatedAtMillis, emergencyUnlock } = await withFreshIdToken(getIdToken, (idToken) =>
        restoreFromPhrase(phrase, idToken)
      );

      // If the phrase resolved to a DORMANT (superseded) vault, nothing has been
      // stored locally yet: bringing it back demotes the current vault, so we ask
      // first (in-app modal), then reactivation is what commits and caches. The
      // demoted vault stays recoverable with its own phrase. When the phrase was
      // an escrowed one, the forced rotation runs AFTER the confirmed reactivation.
      if (!isActiveVault) {
        setReactivatePrompt({ date: new Intl.DateTimeFormat(i18n.language).format(new Date(vaultCreatedAtMillis)) });

        return;
      }

      // Escrowed (emergency) phrase: the trusted contact has seen it, so it must
      // be replaced immediately. Success is reported only once the rotation lands.
      if (emergencyUnlock) {
        await startForcedRotation(publicKey);

        return;
      }

      onSuccess?.(publicKey);
      setStep('restored');
    } catch (err) {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else if (unlockErrorKey(err) === 'errors.vault.wrong_recovery_phrase') setPhraseRejected(true);
      else setError(t(unlockErrorKey(err)));
    } finally {
      setIsPending(false);
    }
  }, [
    restoreInput,
    restoreComplete,
    restoreFromPhrase,
    startForcedRotation,
    getIdToken,
    onSuccess,
    t,
    i18n.language,
    markSessionExpired,
    clearSessionExpired,
  ]);

  // Confirmed reactivation of the dormant vault the phrase unlocked.
  const handleConfirmReactivate = useCallback(async () => {
    setIsPending(true);
    setError(null);

    if (reactivatePrompt?.council) {
      try {
        const reactivated = await withFreshIdToken(getIdToken, (idToken) => councilVault.reactivate(idToken));
        setReactivatePrompt(null);
        await startForcedRotation(reactivated.publicKey);
      } catch (err) {
        if (err instanceof SessionExpiredError) markSessionExpired();
        else setError(t(unlockErrorKey(err)));
      } finally {
        setIsPending(false);
      }

      return;
    }

    try {
      const reactivated = await withFreshIdToken(getIdToken, (idToken) => reactivateVault(restoreInput.trim(), idToken));
      setReactivatePrompt(null);

      // Dormant-vault emergency unlock: reactivation first (just confirmed),
      // THEN the mandatory rotation of the now-active keyring.
      if (reactivated.emergencyUnlock) {
        await startForcedRotation(reactivated.publicKey);

        return;
      }

      onSuccess?.(reactivated.publicKey);
      setStep('restored');
    } catch (err) {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else setError(t(unlockErrorKey(err)));
    } finally {
      setIsPending(false);
    }
  }, [getIdToken, reactivateVault, restoreInput, startForcedRotation, onSuccess, markSessionExpired, t, reactivatePrompt, councilVault]);

  // The council gave the vault back in this browser: the dormant phrase it
  // released is burned by the forced change of the user's own phrase.
  const handleCouncilRecovered = useCallback(
    async (result: CouncilRecoveryResult) => {
      setCouncilUnlock(true);

      if (!result.isActiveVault) {
        setReactivatePrompt({ date: new Intl.DateTimeFormat(i18n.language).format(new Date(result.vaultCreatedAtMillis)), council: true });

        return;
      }

      try {
        await startForcedRotation(result.publicKey);
      } catch (err) {
        setError((err as Error).message);
      }
    },
    [startForcedRotation, i18n.language]
  );

  // Commit the rotated keyring: the moment the escrowed phrase (and the old
  // primary one) dies. The shared flow burns + re-arms every granted
  // relationship on the same PUT; the server rejects the write without them.
  const handleConfirmForcedRotation = useCallback(async () => {
    if (!forcedRotation) return;

    setRotationBusy(true);
    setRotationError(null);
    setRotationBlocked(null);
    clearSessionExpired();

    try {
      const lang = mnemonicLanguageForLocale(i18n.language);
      let council: { councilRearm?: Awaited<ReturnType<typeof councilVault.createEscrow>>; councilDrop?: boolean } | undefined;

      // The council's setup is renewed with a fresh dormant phrase over its
      // current members; if that cannot be built (its membership no longer
      // verifies), the user leaves it and is told to set it up again.
      if (councilUnlock) {
        try {
          const forMe = await withFreshIdToken(getIdToken, fetchCouncilForMe);
          council = {
            councilRearm: await councilVault.createEscrow(forMe.council!.council_id, forMe.council!.chain, lang, forMe.escrow!.record.roster_hash),
          };
        } catch {
          council = { councilDrop: true };
        }
      }

      await commitKeyring(forcedRotation.keyring, lang, council);
      setCouncilDropped(council?.councilDrop === true);
      onSuccess?.(forcedRotation.publicKey);
      setForcedRotation(null);
      setStep('forced-rotation-done');
    } catch (err) {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else if (err instanceof UntrustedRearmError) setRotationBlocked(err.contacts);
      else setRotationError((err as Error).message);
    } finally {
      setRotationBusy(false);
    }
  }, [forcedRotation, commitKeyring, i18n.language, onSuccess, markSessionExpired, clearSessionExpired, councilUnlock, councilVault, getIdToken]);

  // A granted contact is no longer trusted, so their mandatory re-arm cannot be
  // built: revoke exactly those relationships (user-approved), then go on with
  // the step they blocked (generating the phrase, or committing it).
  const handleRotationRevokeAndRetry = useCallback(async () => {
    if (!rotationBlocked) return;

    setRotationBusy(true);
    setRotationError(null);

    try {
      await revokeContacts(rotationBlocked.map((contact) => contact.id));
      setRotationBlocked(null);
    } catch (err) {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else setRotationError((err as Error).message);
      setRotationBusy(false);

      return;
    }

    if (forcedRotation) {
      setRotationBusy(false);
      await handleConfirmForcedRotation();
    } else if (rotationPublicKey) {
      try {
        await startForcedRotation(rotationPublicKey);
      } catch (err) {
        setRotationError((err as Error).message);
      } finally {
        setRotationBusy(false);
      }
    }
  }, [rotationBlocked, revokeContacts, markSessionExpired, forcedRotation, handleConfirmForcedRotation, rotationPublicKey, startForcedRotation]);

  // Warn on tab reload/close while a backup step shows an un-confirmed phrase
  // (initial onboarding backup, or the forced post-emergency rotation).
  useUnsavedPhraseGuard((step === 'backup' && !isCommitting) || (step === 'forced-rotation' && !rotationBusy));

  // The product's close control mid-backup: nothing is on the server yet, so
  // closing throws the setup away. Ask first instead of closing silently.
  useCloseGuard(step === 'backup' && !isCommitting, () => setCancelPrompt(true));

  // The screen the restore was entered from, not `hasExistingBackendKey`: the server
  // check can lead to existing-key-choice while that prop is still a stale false.
  // Only with an active identity does the reset ("Lost phrase?") apply.
  const [restoreFrom, setRestoreFrom] = useState<'existing-key-choice' | 'previous-identity'>('previous-identity');

  const banner = (
    <>
      {sessionExpired && onReconnect && <SessionExpiredAlert onReconnect={onReconnect} onCancel={onCancelAuth} isAuthenticating={isAuthenticating} />}
      {error && <Notice type={VariantType.ERROR}>{error}</Notice>}
    </>
  );

  const deEnrolledNotice = deEnrolledAfterDays !== null && (
    <Notice type={VariantType.INFO}>{t('onboarding.de_enrolled_notice', { count: deEnrolledAfterDays })}</Notice>
  );

  const rotationBlockedNotice = rotationBlocked && (
    <Notice type={VariantType.WARNING}>
      <div className={styles.alertStack}>
        <span>
          {t('emergency.rearm_blocked', {
            names: rotationBlocked.map((contact) => personNameWithEmail(contact.name, contact.email)).join(', '),
          })}
        </span>
        <div>
          <Button size="small" color="error" onClick={handleRotationRevokeAndRetry} disabled={rotationBusy}>
            {t('emergency.rearm_revoke_retry')}
          </Button>
        </div>
      </div>
    </Notice>
  );

  const anotherDeviceButton = onUseAnotherDevice && (
    <Button variant="bordered" color="neutral" onClick={onUseAnotherDevice} icon={<PhoneDesktop aria-hidden />}>
      {t('onboarding.btn_use_another_device')}
    </Button>
  );

  return (
    <>
      <Modal
        isOpen={reactivatePrompt !== null}
        onClose={isPending ? () => undefined : () => setReactivatePrompt(null)}
        closeOnClickOutside={false}
        size={ModalSize.SMALL}
        aria-label={t('onboarding.reactivate_title')}
      >
        <Screen
          title={t('onboarding.reactivate_title')}
          description={
            reactivatePrompt
              ? t(reactivatePrompt.council ? 'council.reactivate_confirm' : 'onboarding.reactivate_confirm', { date: reactivatePrompt.date })
              : ''
          }
          actions={
            <>
              <Button onClick={handleConfirmReactivate} disabled={isPending}>
                {isPending ? t('onboarding.btn_restoring') : t('onboarding.reactivate_confirm_button')}
              </Button>
              <Button variant="bordered" color="neutral" onClick={() => setReactivatePrompt(null)} disabled={isPending}>
                {t('onboarding.btn_cancel')}
              </Button>
            </>
          }
        />
      </Modal>

      {/* Asked by the product's close control while the phrase is unsaved. */}
      <Modal
        isOpen={cancelPrompt}
        onClose={() => setCancelPrompt(false)}
        closeOnClickOutside={false}
        size={ModalSize.SMALL}
        aria-label={t('onboarding.cancel_setup_title')}
      >
        <Screen
          title={t('onboarding.cancel_setup_title')}
          description={t('onboarding.cancel_setup_text')}
          actions={
            <>
              <Button onClick={() => setCancelPrompt(false)}>{t('onboarding.btn_continue_setup')}</Button>
              <Button variant="bordered" color="error" onClick={handleCancelBackup}>
                {t('onboarding.btn_cancel_setup')}
              </Button>
            </>
          }
        />
      </Modal>

      {(step === 'checking-history' || step === 'generating') && (
        <LoadingScreen label={step === 'generating' ? t('onboarding.title_generating') : undefined} />
      )}

      {step === 'explanation' && (
        <Screen
          illustration="shield-gear"
          title={t('onboarding.title_enable')}
          description={
            <p>
              <Trans t={t} i18nKey="onboarding.explanation" components={{ strong: <strong /> }} />
            </p>
          }
          banner={
            <>
              {hasJustReset && <Notice type={VariantType.SUCCESS}>{t('onboarding.reset_success')}</Notice>}
              {banner}
            </>
          }
          actions={
            <Button onClick={handleGenerateKeys} disabled={isPending}>
              {isPending ? t('onboarding.btn_generating') : t('onboarding.btn_continue')}
            </Button>
          }
        >
          <SecurityNotice t={t} />
        </Screen>
      )}

      {step === 'existing-key-choice' && (
        <Screen
          illustration="shield-restore"
          title={t('onboarding.title_existing')}
          description={t('onboarding.existing_recovery_hint')}
          banner={
            <>
              {banner}
              {deEnrolledNotice}
            </>
          }
          actions={
            <Button
              onClick={() => {
                if (restoreMethod === 'device' && onUseAnotherDevice) onUseAnotherDevice();
                else if (restoreMethod === 'council') {
                  setRestoreFrom('existing-key-choice');
                  setStep('council-recovery');
                } else {
                  setRestoreFrom('existing-key-choice');
                  setStep('restore');
                }
              }}
            >
              {t('onboarding.btn_continue')}
            </Button>
          }
        >
          <div className={styles.options} role="radiogroup" aria-label={t('onboarding.title_existing')}>
            {onUseAnotherDevice && (
              <RestoreOption
                selected={restoreMethod === 'device'}
                onSelect={() => setRestoreMethod('device')}
                icon={<PhoneDesktop aria-hidden size={20} />}
                title={t('onboarding.btn_use_another_device')}
                description={t('onboarding.option_device_description')}
              />
            )}
            <RestoreOption
              selected={restoreMethod === 'phrase'}
              onSelect={() => setRestoreMethod('phrase')}
              icon={<Key aria-hidden size={20} />}
              title={t('onboarding.btn_restore_from_backup')}
              description={t('onboarding.option_phrase_description')}
            />
            {councilAvailable && (
              <RestoreOption
                selected={restoreMethod === 'council'}
                onSelect={() => setRestoreMethod('council')}
                icon={<ShieldCheck aria-hidden size={20} />}
                title={t('council.option_title')}
                description={t('council.option_description')}
              />
            )}
          </div>
        </Screen>
      )}

      {step === 'previous-identity' && (
        <Screen
          illustration="shield-restore"
          title={t('onboarding.title_previous_identity')}
          description={
            <>
              <p>{t('onboarding.previous_identity_detected')}</p>
              <p>{t('onboarding.previous_identity_hint')}</p>
            </>
          }
          banner={
            <>
              {banner}
              {deEnrolledNotice}
            </>
          }
          actions={
            <>
              <Button
                onClick={() => {
                  setRestoreFrom('previous-identity');
                  setStep('restore');
                }}
                icon={<Key aria-hidden />}
              >
                {t('onboarding.btn_restore_from_backup')}
              </Button>
              {anotherDeviceButton}
              {councilAvailable && (
                <Button
                  variant="bordered"
                  color="neutral"
                  icon={<ShieldCheck aria-hidden />}
                  onClick={() => {
                    setRestoreFrom('previous-identity');
                    setStep('council-recovery');
                  }}
                >
                  {t('council.option_title')}
                </Button>
              )}
              <Button variant="tertiary" color="neutral" onClick={() => setStep('explanation')}>
                {t('onboarding.btn_start_new_identity')}
              </Button>
            </>
          }
        >
          {helpfulContacts.length > 0 && (
            <div className={`${styles.card} ${styles.contacts}`}>
              <strong>{t('onboarding.previous_identity_contacts_title')}</strong>
              <p>{t('onboarding.previous_identity_contacts_text')}</p>
              <ul className={styles.people}>
                {helpfulContacts.map((contact) => (
                  <li key={contact.id}>
                    <Identity name={contact.name} email={contact.email} />
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Screen>
      )}

      {step === 'council-recovery' && (
        <CouncilRecovery
          getIdToken={getIdToken}
          onBack={() => setStep(restoreFrom)}
          onRecovered={handleCouncilRecovered}
          onReconnect={onReconnect}
          isAuthenticating={isAuthenticating}
          onCancelAuth={onCancelAuth}
          currentIdToken={currentIdToken}
        />
      )}

      {step === 'last-resort' && (
        <LastResortStep isPending={isPending} onConfirm={handleResetFromZero} onBack={() => setStep('restore')} banner={banner} t={t} />
      )}

      {step === 'restore' && (
        <Screen
          back={{
            label: t('onboarding.btn_back'),
            onClick: () => setStep(restoreFrom),
            disabled: isPending,
          }}
          title={t('onboarding.title_restore')}
          description={t('onboarding.restore_description')}
          banner={banner}
          actions={
            <>
              <Button onClick={handleRestoreKeys} disabled={isPending || !restoreComplete || phraseRejected}>
                {isPending ? t('onboarding.btn_restoring') : t('onboarding.btn_restore')}
              </Button>
              {restoreFrom === 'existing-key-choice' && (
                <Button variant="bordered" color="neutral" onClick={() => setStep('last-resort')} disabled={isPending}>
                  {t('onboarding.btn_last_resort')}
                </Button>
              )}
            </>
          }
        >
          <RecoveryPhraseInput
            invalid={phraseRejected}
            onChange={(phrase, complete) => {
              setRestoreInput(phrase);
              setRestoreComplete(complete);
              setPhraseRejected(false);
            }}
          />
          {phraseRejected && (
            <p className={styles.errorText} role="alert">
              {t('errors.vault.wrong_recovery_phrase')}
            </p>
          )}
        </Screen>
      )}

      {step === 'restored' && (
        <Screen
          illustration="shield-check"
          title={t('onboarding.title_enabled')}
          description={t('onboarding.restored_description')}
          actions={<Button onClick={onClose}>{t('settings.done')}</Button>}
        />
      )}

      {/* Replacing an identity: the commit waits on a step-up, and nothing else on
          the backup screen matters until it is done. */}
      {step === 'backup' && backupPassphrase && stepUpState !== 'idle' && (
        <StepUpScreen
          state={stepUpState}
          onStepUp={onStepUp}
          onCancel={onCancelAuth}
          isAuthenticating={isAuthenticating}
          note={t('onboarding.step_up_phrase_kept')}
        />
      )}

      {step === 'backup' && backupPassphrase && stepUpState === 'idle' && (
        <RecoveryKitBackup
          passphrase={backupPassphrase}
          alreadySaved={confirmedPassphrase === backupPassphrase}
          parentOrigin={parentOrigin}
          onConfirm={() => {
            setConfirmedPassphrase(backupPassphrase);
            void handleCommitOnboarding();
          }}
          confirmLabel={t('onboarding.btn_backup_done')}
          busyLabel={t('onboarding.finalizing')}
          isBusy={isCommitting}
          error={commitError}
          banner={banner}
        />
      )}

      {/* Success screen after the kit backup is confirmed, with the one-time
          trusted-contact suggestion (our recommended fallback if the kit is lost). */}
      {step === 'done' && (
        <Screen
          illustration="shield-check"
          title={t('onboarding.title_enabled')}
          description={
            <>
              <p>{t('onboarding.enabled_description')}</p>
              {onOpenEmergencyAccess && <p>{t('emergency.nudge_text')}</p>}
            </>
          }
          actions={
            <>
              <Button onClick={onClose}>{t('settings.done')}</Button>
              {onOpenEmergencyAccess && (
                <Button variant="bordered" color="neutral" onClick={onOpenEmergencyAccess}>
                  {t('emergency.nudge_button')}
                </Button>
              )}
            </>
          }
        />
      )}

      {/* Mandatory rotation after an emergency unlock: no skip, no cancel. A
          contact blocking it is dealt with before any phrase is shown. */}
      {step === 'forced-rotation' && !forcedRotation && rotationBlocked && (
        <Screen
          illustration="shield-gear"
          title={t('emergency.rotation_title')}
          description={t('emergency.rotation_explanation')}
          banner={
            <>
              {banner}
              {rotationBlockedNotice}
              {rotationError && <Notice type={VariantType.ERROR}>{rotationError}</Notice>}
            </>
          }
        />
      )}
      {step === 'forced-rotation' && forcedRotation && (
        <RecoveryKitBackup
          title={t('emergency.rotation_title')}
          description={
            councilUnlock ? (
              <>
                <p>{t('council.rotation_explanation')}</p>
                <p>{t('council.rotation_rearm_note')}</p>
              </>
            ) : (
              <>
                <p>{t('emergency.rotation_explanation')}</p>
                <p>{t('emergency.rotation_rearm_note')}</p>
              </>
            )
          }
          banner={
            <>
              {banner}
              {rotationBlockedNotice}
            </>
          }
          passphrase={forcedRotation.recoveryPhrase}
          parentOrigin={parentOrigin}
          onConfirm={handleConfirmForcedRotation}
          confirmLabel={t('settings.change_phrase_confirm_saved')}
          busyLabel={t('settings.change_phrase_applying')}
          isBusy={rotationBusy}
          error={rotationError}
        />
      )}

      {step === 'forced-rotation-done' && (
        <Screen
          illustration="shield-check"
          title={t('emergency.rotation_title')}
          description={councilUnlock ? t('council.rotation_done') : t('emergency.rotation_done')}
          banner={councilDropped && <Notice type={VariantType.WARNING}>{t('council.rotation_dropped')}</Notice>}
          actions={<Button onClick={onClose}>{t('settings.done')}</Button>}
        />
      )}
    </>
  );
}

function RestoreOption({
  selected,
  onSelect,
  icon,
  title,
  description,
}: {
  selected: boolean;
  onSelect: () => void;
  icon: ReactNode;
  title: string;
  description: string;
}) {
  // A native radio inside its card: arrow keys move between the options and the
  // group is a single tab stop, as screen reader users expect.
  return (
    <label className={selected ? `${styles.option} ${styles.optionSelected}` : styles.option}>
      <input type="radio" name="restore-method" className={styles.optionInput} checked={selected} onChange={onSelect} />
      <span className={styles.optionIcon}>{icon}</span>
      <span className={styles.optionText}>
        <span className={styles.optionTitle}>{title}</span>
        <span className={styles.optionDescription}>{description}</span>
      </span>
    </label>
  );
}

/**
 * Security notice about browser extensions.
 * Shown during onboarding and key restoration to remind users
 * that browser extensions can potentially access page content.
 */
function SecurityNotice({ t }: { t: TFunction }) {
  return <Notice type={VariantType.INFO}>{t('onboarding.extensions_warning')}</Notice>;
}
