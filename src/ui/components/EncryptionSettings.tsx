import { Button, Checkbox, Modal, ModalSize, Radio, RadioGroup, VariantType } from '@gouvfr-lasuite/ui-components';
import { Eye, PhoneDesktop, ShieldAlert, ShieldCheck, ShieldOff } from '@gouvfr-lasuite/ui-components/icons';
import { type ReactNode, useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import { mnemonicLanguageForLocale } from '@encryption/src/crypto/mnemonic';
import { MSG_VAULT_DESTROY_KEYS } from '@encryption/src/shared/constants';
import type { VaultKeyringWire } from '@encryption/src/shared/schemas/vault';
import type { UserInfo } from '@encryption/src/ui/App';
import { fetchCouncilForMe, fetchMyCouncils } from '@encryption/src/ui/api/council-client';
import { fetchTrustedContacts } from '@encryption/src/ui/api/emergency-client';
import {
  deletePublicKeys,
  fetchNextKeyVersion,
  fetchPublicKeys,
  registerKeyComplete,
  registerKeyInit,
} from '@encryption/src/ui/api/public-keys-client';
import { SessionExpiredError, withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { RecoveryKitBackup } from '@encryption/src/ui/components/RecoveryKitBackup';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
import { SyncIntegrityAlert } from '@encryption/src/ui/components/SyncIntegrityAlert';
import {
  type BlockedContact,
  UntrustedRearmError,
  grantedRearmRows,
  personNameWithEmail,
} from '@encryption/src/ui/components/emergency-access-logic';
import { Chip, CopyFingerprintButton, FingerprintBoxes, IdentityCard } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { useCloseGuard } from '@encryption/src/ui/hooks/useCloseRequest';
import { useKeyringCommit } from '@encryption/src/ui/hooks/useKeyringCommit';
import { useModalSize } from '@encryption/src/ui/hooks/useModalSize';
import { useSessionExpired } from '@encryption/src/ui/hooks/useSessionExpired';
import { useUnsavedPhraseGuard } from '@encryption/src/ui/hooks/useUnsavedPhraseGuard';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

/** The flows of this screen a product can open on their own (see SettingsSection). */
export type EncryptionSettingsSection = 'manage' | 'verification-code' | 'recovery-phrase';

type View = 'home' | EncryptionSettingsSection;

type RemoteStatus = 'checking' | 'in-sync' | 'remote-disabled' | 'remote-never' | 'remote-diverged';

interface EncryptionSettingsProps {
  userInfo?: UserInfo | null;
  userId?: string | null;
  getIdToken: () => Promise<string | null>;
  /**
   * Opened for one flow from a product's own account page: that flow is shown
   * alone, without the home, and closes the interface once it ends.
   */
  section?: EncryptionSettingsSection | null;
  onClose: () => void;
  onKeysDestroyed: () => void;
  /** No keys on this device: start the onboarding. */
  onSetUp?: () => void;
  onOpenDeviceApproval?: () => void;
  onOpenEmergencyAccess?: () => void;
  onOpenRecoveryCouncil?: () => void;
  onOpenCustodian?: () => void;
  onReconnect?: () => void;
  isAuthenticating?: boolean;
  onCancelAuth?: () => void;
  currentIdToken?: string | null;
}

function SettingsRow({ title, description, action }: { title: string; description: string; action: ReactNode }) {
  return (
    <div className={styles.settingsRow}>
      <div className={styles.settingsRowText}>
        <p className={styles.settingsRowTitle}>{title}</p>
        <p className={styles.settingsRowDescription}>{description}</p>
      </div>
      {action}
    </div>
  );
}

function StatusBanner({ tone, icon, label, action }: { tone: 'success' | 'warning' | 'neutral'; icon: ReactNode; label: string; action: ReactNode }) {
  const toneClass = tone === 'success' ? styles.statusSuccess : tone === 'warning' ? styles.statusWarning : '';

  return (
    <div className={`${styles.status} ${toneClass}`} role="status">
      {icon}
      <span className={styles.statusLabel}>{label}</span>
      {action}
    </div>
  );
}

export function EncryptionSettings({
  userInfo = null,
  userId = null,
  getIdToken,
  section = null,
  onClose,
  onKeysDestroyed,
  onSetUp,
  onOpenDeviceApproval,
  onOpenEmergencyAccess,
  onOpenRecoveryCouncil,
  onOpenCustodian,
  onReconnect,
  isAuthenticating = false,
  onCancelAuth,
  currentIdToken = null,
}: EncryptionSettingsProps) {
  const { t, i18n } = useTranslation('common');
  const { isReady, hasKeys, getPublicKey, request, changeRecoveryPhrase, signKeyRegistration, respondToKeyChallenge, syncVault } =
    useEncryptionContext();

  const [view, setView] = useState<View>(section ?? 'home');
  // A flow opened on its own ends by closing the interface; reached from the home,
  // it comes back to it.
  const leaveView = useCallback(() => {
    if (section) onClose();
    else setView('home');
  }, [section, onClose]);
  const backToHome = section ? undefined : { label: t('onboarding.btn_back'), onClick: () => setView('home') };

  // The home lays rows and their buttons side by side, in the column of an account
  // page: the large modal.
  useModalSize('large', view === 'home');

  // Stepped, deferred-commit change-recovery-phrase flow:
  //   warning (existing backups will be invalidated) -> backup (full Recovery Kit
  //   UX) -> commit on confirm -> done. The re-wrapped keyring is held locally and
  //   only sent to the server (invalidating the old phrase) once the user confirms
  //   they saved the new one, so cancelling leaves everything intact.
  const [changePhraseStep, setChangePhraseStep] = useState<'warning' | 'backup' | 'done'>('warning');
  const [pendingKeyring, setPendingKeyring] = useState<VaultKeyringWire | null>(null);
  const [newRecoveryPhrase, setNewRecoveryPhrase] = useState<string | null>(null);
  const [isChangingPhrase, setIsChangingPhrase] = useState(false);
  const [changeError, setChangeError] = useState<string | null>(null);
  // Session-expired banner state (mirrors the onboarding modal). The commit step
  // can run minutes after generating (the user is saving their phrase), so the
  // ID token may have lapsed by then; show the reconnect banner instead of a raw
  // error and let the user retry once reconnected (the pending keyring is kept).
  const { sessionExpired, markSessionExpired } = useSessionExpired(currentIdToken, isAuthenticating);

  const openChangePhrase = useCallback(() => {
    setChangeError(null);
    setChangePhraseStep('warning');
    setView('recovery-phrase');
  }, []);

  // Commit the new keyring to the server. This is the moment the OLD phrase (and
  // all its backups) stops working, so it runs only after the user confirms.
  // Goes through the shared keyring-commit flow: while a recovery is granted the
  // server rejects the rewrite unless the granted escrows are burned + re-armed,
  // so a routine phrase change carries the mandatory re-arms too.
  const { commitKeyring, findBlockedContacts, revokeContacts } = useKeyringCommit(getIdToken);
  const [rearmBlocked, setRearmBlocked] = useState<BlockedContact[] | null>(null);

  // Generate the new phrase + re-wrap the keyring LOCALLY (no server call yet),
  // once no granted contact would block its commit: the user is never handed a
  // phrase to save that could not take effect.
  const handleGeneratePhrase = useCallback(async () => {
    setIsChangingPhrase(true);
    setChangeError(null);
    setRearmBlocked(null);

    try {
      // Advisory: the commit enforces the same condition, so only an expired
      // session (which the commit would hit too) stops here.
      const blocked = await findBlockedContacts().catch((err: unknown) => {
        if (err instanceof SessionExpiredError) throw err;

        return [];
      });
      if (blocked.length > 0) {
        setRearmBlocked(blocked);

        return;
      }

      const lang = mnemonicLanguageForLocale(i18n.language);
      const { recoveryPhrase, keyring } = await changeRecoveryPhrase(lang);
      setPendingKeyring(keyring);
      setNewRecoveryPhrase(recoveryPhrase);
      setChangePhraseStep('backup');
    } catch (err) {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else setChangeError((err as Error).message);
    } finally {
      setIsChangingPhrase(false);
    }
  }, [findBlockedContacts, changeRecoveryPhrase, i18n.language, markSessionExpired]);

  const handleConfirmPhraseBackup = useCallback(async () => {
    if (!pendingKeyring) return;

    setIsChangingPhrase(true);
    setChangeError(null);
    setRearmBlocked(null);

    try {
      await commitKeyring(pendingKeyring, mnemonicLanguageForLocale(i18n.language));
      setPendingKeyring(null);
      setNewRecoveryPhrase(null);
      setChangePhraseStep('done');
    } catch (err) {
      // Keep the pending keyring + phrase so the user can retry after reconnecting;
      // the phrase they just saved stays valid.
      if (err instanceof SessionExpiredError) {
        markSessionExpired();
      } else if (err instanceof UntrustedRearmError) {
        setRearmBlocked(err.contacts);
      } else {
        setChangeError((err as Error).message);
      }
    } finally {
      setIsChangingPhrase(false);
    }
  }, [pendingKeyring, commitKeyring, i18n.language, markSessionExpired]);

  // A granted contact is no longer trusted, so their mandatory re-arm cannot be
  // built: revoke exactly those relationships (user-approved), then go on with
  // the step they blocked (generating the phrase, or, should their status have
  // changed meanwhile, committing it).
  const handleRevokeBlockedAndRetry = useCallback(async () => {
    if (!rearmBlocked) return;

    setIsChangingPhrase(true);
    setChangeError(null);

    try {
      await revokeContacts(rearmBlocked.map((contact) => contact.id));
      setRearmBlocked(null);
    } catch (err) {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else setChangeError((err as Error).message);
      setIsChangingPhrase(false);

      return;
    }

    setIsChangingPhrase(false);
    await (changePhraseStep === 'backup' ? handleConfirmPhraseBackup() : handleGeneratePhrase());
  }, [rearmBlocked, revokeContacts, markSessionExpired, changePhraseStep, handleConfirmPhraseBackup, handleGeneratePhrase]);

  // Back out before committing: nothing was sent to the server, so just drop the
  // unsaved phrase and re-wrapped keyring. The current phrase keeps working.
  const handleCancelPhrase = useCallback(() => {
    setPendingKeyring(null);
    setNewRecoveryPhrase(null);
    setChangeError(null);
    setRearmBlocked(null);
    setChangePhraseStep('warning');
    leaveView();
  }, [leaveView]);

  // Divergence between this device's identity and the server directory. The
  // local keys alone would hide a disable/rotation performed from another device.
  // remote-disabled: an identity was registered then disabled elsewhere (re-enable
  // is legitimate). remote-never: no identity was EVER registered for this user
  // (an orphaned local vault): re-enabling would push a directory entry with no
  // vault, so we only offer a clean re-onboard.
  const [remoteStatus, setRemoteStatus] = useState<RemoteStatus>('checking');
  const [remoteFingerprint, setRemoteFingerprint] = useState<string | null>(null);
  const [reconciling, setReconciling] = useState(false);
  const [reconcileError, setReconcileError] = useState<string | null>(null);

  // Reconciliation choice A: bring THIS device's identity back as the active one.
  // WARM path: this device already holds the keys + VRK, so it proves ownership by
  // re-registering its existing keys (both PoPs), NOT with the recovery phrase.
  // The server's reactivate path re-enables the identity + its encryption key AND
  // flips the vault keyring active (superseding a disabled identity, or one another
  // device registered). No phrase, no VRK release: the device already has it.
  const handleReactivateIdentity = useCallback(async () => {
    if (!userId) return;

    setReconciling(true);
    setReconcileError(null);

    try {
      await withFreshIdToken(getIdToken, async (idToken) => {
        const next = await fetchNextKeyVersion(idToken);
        const reg = await signKeyRegistration(next.next_version, Date.now());
        const init = await registerKeyInit(idToken, {
          user_id: userId,
          encryption_public_key: reg.encryptionPublicKey,
          signature_public_key: reg.signaturePublicKey,
          version: reg.version,
          created_at_millis: reg.createdAtMillis,
          key_binding_signature: reg.keyBindingSignature,
        });
        const { response, challengeSignature } = await respondToKeyChallenge(init.challenge_id, init.ciphertext);

        await registerKeyComplete(idToken, { challenge_id: init.challenge_id, response, challenge_signature: challengeSignature });
      });
      setRemoteStatus('in-sync');
      // Turned back on from the review: that was the whole flow.
      leaveView();
    } catch (err) {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else setReconcileError((err as Error).message);
    } finally {
      setReconciling(false);
    }
  }, [userId, getIdToken, signKeyRegistration, respondToKeyChallenge, markSessionExpired, leaveView]);

  // Reconciliation choice B: adopt the SERVER's identity instead. This device's
  // local keys are the wrong identity, so discard them and re-acquire the active
  // one from a device that holds it (device approval) or its recovery phrase.
  // Asked in-app (never window.confirm) before adopting the server's identity,
  // since that deletes this device's keys.
  const [adoptPrompt, setAdoptPrompt] = useState(false);
  const handleAdoptServerIdentity = useCallback(async () => {
    setAdoptPrompt(false);

    try {
      await request(MSG_VAULT_DESTROY_KEYS);
    } catch {
      // Best-effort: proceed to re-acquire regardless.
    }

    if (onOpenDeviceApproval) onOpenDeviceApproval();
    else onKeysDestroyed();
  }, [request, onOpenDeviceApproval, onKeysDestroyed]);

  // Warn on tab reload/close while the new (un-committed, unsaved) phrase is shown.
  useUnsavedPhraseGuard(view === 'recovery-phrase' && changePhraseStep === 'backup' && !isChangingPhrase);

  const [keysExist, setKeysExist] = useState<boolean | null>(null);
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  // The turn-off choice, also reached from the reconciliation screens.
  const [turnOffShown, setTurnOffShown] = useState(false);
  const [confirmDataLoss, setConfirmDataLoss] = useState(false);
  const [alsoDisableServer, setAlsoDisableServer] = useState(false);
  const [isPending, setIsPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // A contact whose recovery is currently GRANTED holds (or can obtain) a working
  // emergency phrase for this vault. The unlock modal walks the user through the
  // mandatory rotation right after an emergency unlock, but nothing stops them
  // closing it: the server keeps the escrow exercisable until the phrase actually
  // changes. So the state is re-derived here and surfaced persistently, since it
  // is exactly what `useKeyringCommit` will burn on the next phrase change.
  const [liveEmergencyPhrases, setLiveEmergencyPhrases] = useState<string[]>([]);

  useEffect(() => {
    if (!keysExist) return;

    let cancelled = false;

    withFreshIdToken(getIdToken, (idToken) => fetchTrustedContacts(idToken))
      .then(({ contacts }) => {
        if (!cancelled) setLiveEmergencyPhrases(grantedRearmRows(contacts, Date.now()).map((row) => row.granteeName));
      })
      .catch(() => {
        // Advisory banner only: a failed fetch must not break the settings screen.
      });

    return () => {
      cancelled = true;
    };
  }, [keysExist, getIdToken, changePhraseStep]);

  // The council rows appear only for someone a council covers, and for its
  // custodians: the interface never learns more than "you are a custodian".
  const [council, setCouncil] = useState<{ covered: boolean; custodian: boolean; pending: number }>({ covered: false, custodian: false, pending: 0 });

  useEffect(() => {
    if (!keysExist) return;

    let cancelled = false;

    withFreshIdToken(getIdToken, async (idToken) => {
      const [forMe, mine] = await Promise.all([fetchCouncilForMe(idToken).catch(() => null), fetchMyCouncils(idToken).catch(() => null)]);
      const councils = mine?.councils ?? [];

      return {
        covered: forMe?.council != null,
        custodian: councils.length > 0,
        pending: councils.reduce(
          (sum, c) => sum + c.requests.filter((r) => r.can_contribute).length + (c.proposal?.may_sign && !c.proposal.signed_by_me ? 1 : 0),
          0
        ),
      };
    })
      .then((state) => {
        if (!cancelled) setCouncil(state);
      })
      .catch(() => {
        // Optional rows: a failed fetch leaves them hidden.
      });

    return () => {
      cancelled = true;
    };
  }, [keysExist, getIdToken]);

  useEffect(() => {
    if (!isReady) return;

    hasKeys()
      .then(({ hasKeys: exists }) => {
        setKeysExist(exists);

        if (exists) {
          getPublicKey().then(({ signaturePublicKey }) => {
            if (signaturePublicKey) {
              computeKeyFingerprint(signaturePublicKey).then(setFingerprint);
            } else {
              setFingerprint(null);
            }
          });
        }
      })
      .catch(() => {
        // Auth may not be set yet: retried when isReady changes.
      });
  }, [isReady, hasKeys, getPublicKey]);

  // Compare the local identity (signature fingerprint) against the server's
  // currently ACTIVE registration. Only identity-level divergence matters here:
  //   - remote-disabled: a key was registered then disabled (re-enable is valid);
  //   - remote-never: no key was ever registered (orphaned local vault);
  //   - remote-diverged: the active key belongs to a different identity than
  //     this device (another device rotated/recreated it).
  // A network error is treated as in-sync so we never raise a false alarm.
  // Re-enter the checking state when the identity under comparison changes, while
  // rendering (a state write inside the effect would render twice).
  const identityUnderCheck = `${userId ?? ''}|${fingerprint ?? ''}`;
  const [checkedIdentity, setCheckedIdentity] = useState(identityUnderCheck);

  if (identityUnderCheck !== checkedIdentity) {
    setCheckedIdentity(identityUnderCheck);
    setRemoteStatus('checking');
  }

  useEffect(() => {
    if (!fingerprint || !userId) return;

    let cancelled = false;

    fetchPublicKeys({ user_ids: [userId] })
      .then(async (data) => {
        const remote = data.keys[0];

        if (!remote) {
          // No ACTIVE key on the server. Distinguish "registered then disabled"
          // (re-enable is legitimate) from "never registered at all" (an orphaned
          // local identity that must not be pushed). The per-user version/generation
          // counters include disabled rows, so generation > 1 means a prior
          // registration existed. If we can't tell (network/session), fall back to
          // the disabled path: the server guard still refuses an illegitimate
          // re-register.
          let everRegistered = true;
          try {
            const next = await withFreshIdToken(getIdToken, (idToken) => fetchNextKeyVersion(idToken));
            everRegistered = next.next_generation > 1;
          } catch {
            // Keep the conservative default (offer re-enable, backed by the server guard).
          }

          if (!cancelled) {
            setRemoteFingerprint(null);
            setRemoteStatus(everRegistered ? 'remote-disabled' : 'remote-never');
          }

          return;
        }

        const remoteFp = await computeKeyFingerprint(remote.signature_public_key);

        if (cancelled) return;

        setRemoteFingerprint(remoteFp);
        setRemoteStatus(remoteFp === fingerprint ? 'in-sync' : 'remote-diverged');
      })
      .catch(() => {
        if (!cancelled) setRemoteStatus('in-sync');
      });

    return () => {
      cancelled = true;
    };
  }, [fingerprint, userId, getIdToken]);

  // Once the identity matches the directory, check that the vault stored on the
  // server still verifies. The vault already retries once and tells a divergence
  // apart; a lasting 'integrity-error' means syncing is paused on this device.
  const [syncIntegrityFailed, setSyncIntegrityFailed] = useState(false);
  const [isRecheckingSync, setIsRecheckingSync] = useState(false);

  useEffect(() => {
    if (remoteStatus !== 'in-sync' || !keysExist) return;

    let cancelled = false;

    syncVault(null)
      .then((result) => {
        if (!cancelled) setSyncIntegrityFailed(result.status === 'integrity-error');
      })
      .catch(() => {
        // Offline or not enrolled: nothing to report about integrity.
      });

    return () => {
      cancelled = true;
    };
  }, [remoteStatus, keysExist, syncVault]);

  const handleRecheckSync = useCallback(async () => {
    setIsRecheckingSync(true);

    try {
      const result = await syncVault(null);
      setSyncIntegrityFailed(result.status === 'integrity-error');
    } catch {
      // Offline: keep the current state, the user can try again.
    } finally {
      setIsRecheckingSync(false);
    }
  }, [syncVault]);

  // The account can only be turned off while it is on: once disabled (or never
  // registered), only this device's keys are left to remove.
  const accountScopeAvailable = remoteStatus === 'in-sync' || remoteStatus === 'checking';
  const disableServer = alsoDisableServer && accountScopeAvailable;

  const handleTurnOff = useCallback(async () => {
    if (!confirmDataLoss) return;

    setIsPending(true);
    setError(null);

    try {
      // Disable the public key in the directory FIRST (if requested), so others
      // stop using a key this user can no longer decrypt with. This is a soft,
      // reversible disable, NOT a destructive vault wipe (a stolen ID token must never
      // be able to destroy the vault; only reading unreadable ciphertext is
      // acceptable). withFreshIdToken (never a raw getIdToken) guarantees a valid
      // token or throws SessionExpiredError: a lapsed session must surface the
      // reconnect banner and ABORT here, never silently skip the disable and then
      // wipe local keys, which would leave this device empty while the server key
      // stays active (and the next screen wrongly reads "existing configuration").
      if (disableServer) {
        await withFreshIdToken(getIdToken, (idToken) => deletePublicKeys(idToken));
      }

      // Only now remove this device's local keys + vault cache. The server vault
      // is left intact so other devices and the recovery phrase keep working.
      await request(MSG_VAULT_DESTROY_KEYS);
      setKeysExist(false);
      setFingerprint(null);
      setTurnOffShown(false);
      onKeysDestroyed();
    } catch (err) {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else setError((err as Error).message);
    } finally {
      setIsPending(false);
    }
  }, [confirmDataLoss, disableServer, getIdToken, request, onKeysDestroyed, markSessionExpired]);

  const resetTurnOff = useCallback(() => {
    setTurnOffShown(false);
    setConfirmDataLoss(false);
    setAlsoDisableServer(false);
    setError(null);
  }, []);

  // The product's close control while the new phrase is unsaved: dropping it is
  // harmless (nothing was sent yet), but make the choice explicit.
  const [cancelPrompt, setCancelPrompt] = useState(false);
  useCloseGuard(view === 'recovery-phrase' && changePhraseStep === 'backup' && !isChangingPhrase, () => setCancelPrompt(true));

  const displayName = userInfo?.name || userInfo?.email || t('settings.you');
  const displayEmail = userInfo?.name ? userInfo.email : null;

  const sessionBanner = sessionExpired && onReconnect && (
    <SessionExpiredAlert onReconnect={onReconnect} onCancel={onCancelAuth} isAuthenticating={isAuthenticating} />
  );

  if (keysExist === null) {
    return <LoadingScreen label={t('settings.loading')} />;
  }

  const outOfSync = keysExist && remoteStatus !== 'checking' && remoteStatus !== 'in-sync';

  // ---------------------------------------------------------------------------
  // Turn off encryption ("Manage encryption"): this device only, or the account.
  // ---------------------------------------------------------------------------
  // The "I understand" tick is the only confirmation: leaving the screen or changing
  // the scope must never carry it over.
  const turnOffScreen = (back?: { label: string; onClick: () => void; disabled?: boolean }, onCancel?: () => void) => (
    <Screen
      back={
        back && {
          ...back,
          onClick: () => {
            resetTurnOff();
            back.onClick();
          },
        }
      }
      title={t('settings.manage_title')}
      banner={
        <>
          {sessionBanner}
          {error && <Notice type={VariantType.ERROR}>{error}</Notice>}
        </>
      }
      actionsLayout="row"
      actions={
        <>
          <Button
            variant="bordered"
            color="neutral"
            onClick={() => {
              resetTurnOff();
              (onCancel ?? leaveView)();
            }}
            disabled={isPending}
          >
            {t('settings.change_phrase_cancel')}
          </Button>
          <Button color="error" onClick={handleTurnOff} disabled={isPending || !confirmDataLoss}>
            {isPending ? t('settings.deleting') : t('settings.turn_off_button')}
          </Button>
        </>
      }
    >
      <RadioGroup>
        <Radio
          name="delete-scope"
          label={t('settings.delete_scope_device')}
          text={t('settings.delete_scope_device_hint')}
          checked={!disableServer}
          onChange={() => {
            setAlsoDisableServer(false);
            setConfirmDataLoss(false);
          }}
        />
        {accountScopeAvailable && (
          <Radio
            name="delete-scope"
            label={t('settings.delete_scope_account')}
            text={t('settings.delete_scope_account_hint')}
            checked={disableServer}
            onChange={() => {
              setAlsoDisableServer(true);
              setConfirmDataLoss(false);
            }}
          />
        )}
      </RadioGroup>

      <Notice type={VariantType.ERROR}>
        <div className={styles.alertStack}>
          <span>{disableServer ? t('settings.disable_server_warning') : t('settings.delete_warning_backup')}</span>
          <Checkbox label={t('onboarding.i_understand')} checked={confirmDataLoss} onChange={() => setConfirmDataLoss(!confirmDataLoss)} />
        </div>
      </Notice>
    </Screen>
  );

  if (turnOffShown) {
    return turnOffScreen({ label: t('onboarding.btn_back'), onClick: resetTurnOff, disabled: isPending }, resetTurnOff);
  }

  // ---------------------------------------------------------------------------
  // Reconciliation: this device's identity disagrees with the server directory.
  // Reviewed from the "Manage" flow (and opened by the home's banner).
  // ---------------------------------------------------------------------------
  const reconcileBanner = (
    <>
      {sessionBanner}
      {reconcileError && <Notice type={VariantType.ERROR}>{reconcileError}</Notice>}
    </>
  );
  const turnOffDeviceButton = (
    <Button variant="bordered" color="error" onClick={() => setTurnOffShown(true)} disabled={reconciling}>
      {t('settings.reconcile_delete_local')}
    </Button>
  );

  if (view === 'manage' && outOfSync) {
    // remote-never has no legitimate re-enable: the identity was never on the
    // server, so the only coherent action is to remove the orphaned local keys
    // and onboard from scratch.
    if (remoteStatus === 'remote-never') {
      return (
        <Screen
          back={backToHome}
          illustration="shield-x"
          title={t('settings.remote_never_title')}
          descriptionSize="xs"
          description={
            <>
              <p>{t('settings.remote_never_warning')}</p>
              <p>{t('settings.remote_never_hint')}</p>
            </>
          }
          banner={reconcileBanner}
          actions={
            <Button onClick={() => setTurnOffShown(true)} disabled={reconciling}>
              {t('settings.reconcile_onboard_fresh')}
            </Button>
          }
        />
      );
    }

    if (remoteStatus === 'remote-disabled') {
      return (
        <Screen
          back={backToHome}
          title={t('settings.remote_disabled_title')}
          descriptionSize="xs"
          description={t('settings.remote_disabled_warning')}
          banner={reconcileBanner}
          actions={
            <>
              <Button onClick={handleReactivateIdentity} disabled={reconciling}>
                {reconciling ? t('settings.reconcile_working') : t('settings.reconcile_reenable')}
              </Button>
              {turnOffDeviceButton}
            </>
          }
        />
      );
    }

    return (
      <>
        <Modal
          isOpen={adoptPrompt}
          onClose={() => setAdoptPrompt(false)}
          closeOnClickOutside={false}
          size={ModalSize.SMALL}
          aria-label={t('settings.reconcile_adopt_title')}
        >
          <Screen
            title={t('settings.reconcile_adopt_title')}
            description={t('settings.reconcile_adopt_confirm')}
            actions={
              <>
                <Button onClick={() => setAdoptPrompt(false)}>{t('onboarding.btn_go_back')}</Button>
                <Button variant="bordered" color="error" onClick={handleAdoptServerIdentity}>
                  {t('settings.reconcile_adopt_button')}
                </Button>
              </>
            }
          />
        </Modal>
        <Screen
          back={backToHome}
          title={t('settings.remote_diverged_title')}
          descriptionSize="xs"
          description={t('settings.remote_diverged_warning')}
          banner={reconcileBanner}
          actions={
            <>
              <Button onClick={() => setAdoptPrompt(true)} disabled={reconciling}>
                {t('settings.reconcile_adopt_server')}
              </Button>
              <Button variant="secondary" onClick={handleReactivateIdentity} disabled={reconciling}>
                {reconciling ? t('settings.reconcile_working') : t('settings.reconcile_keep_local')}
              </Button>
              {turnOffDeviceButton}
            </>
          }
        >
          {fingerprint && (
            <IdentityCard
              name={displayName}
              secondary={displayEmail}
              tone="warning"
              aside={
                <Chip tone="warning" icon="warning">
                  {t('settings.key_mismatch')}
                </Chip>
              }
            >
              <div>
                <p className={styles.groupLabel}>{t('settings.remote_this_device')}</p>
                <FingerprintBoxes fingerprint={fingerprint} tone="warning" />
              </div>
              {remoteFingerprint && (
                <div>
                  <p className={styles.groupLabel}>{t('settings.remote_server')}</p>
                  <FingerprintBoxes fingerprint={remoteFingerprint} />
                </div>
              )}
            </IdentityCard>
          )}
          <p className={styles.hint}>{t('settings.reconcile_diverged_hint')}</p>
        </Screen>
      </>
    );
  }

  // A flow that needs keys on this device, opened on a device without any.
  if (view !== 'home' && !keysExist) {
    return (
      <Screen
        illustration="shield-gear"
        title={t('settings.no_keys_title')}
        description={t('settings.no_keys')}
        actions={onSetUp && <Button onClick={onSetUp}>{t('settings.set_up')}</Button>}
      />
    );
  }

  if (view === 'manage') {
    return turnOffScreen(backToHome);
  }

  // ---------------------------------------------------------------------------
  // Verification code: the identity fingerprint others compare out of band.
  // ---------------------------------------------------------------------------
  if (view === 'verification-code') {
    return (
      <Screen
        back={backToHome}
        title={t('settings.verification_code_title')}
        description={t('settings.verification_code_description')}
        descriptionSize="xs"
      >
        {fingerprint ? (
          <IdentityCard
            name={displayName}
            secondary={displayEmail}
            fingerprint={fingerprint}
            aside={<CopyFingerprintButton fingerprint={fingerprint} />}
          />
        ) : (
          <LoadingScreen />
        )}
      </Screen>
    );
  }

  // ---------------------------------------------------------------------------
  // Change the recovery phrase.
  // ---------------------------------------------------------------------------
  if (view === 'recovery-phrase') {
    const rearmBlockedNotice = rearmBlocked && (
      <Notice type={VariantType.WARNING}>
        <div className={styles.alertStack}>
          <span>
            {t('emergency.rearm_blocked', {
              names: rearmBlocked.map((contact) => personNameWithEmail(contact.name, contact.email)).join(', '),
            })}
          </span>
          <div>
            <Button size="small" color="error" onClick={handleRevokeBlockedAndRetry} disabled={isChangingPhrase}>
              {t('emergency.rearm_revoke_retry')}
            </Button>
          </div>
        </div>
      </Notice>
    );

    // The backup step takes over the whole view, like the onboarding backup screen.
    if (changePhraseStep === 'backup' && newRecoveryPhrase) {
      return (
        <>
          <Modal
            isOpen={cancelPrompt}
            onClose={() => setCancelPrompt(false)}
            closeOnClickOutside={false}
            size={ModalSize.SMALL}
            aria-label={t('settings.cancel_change_title')}
          >
            <Screen
              title={t('settings.cancel_change_title')}
              description={t('settings.cancel_change_text')}
              actions={
                <>
                  <Button onClick={() => setCancelPrompt(false)}>{t('settings.cancel_change_continue')}</Button>
                  <Button
                    variant="bordered"
                    color="error"
                    onClick={() => {
                      setCancelPrompt(false);
                      handleCancelPhrase();
                      // A flow opened on its own is already closed by handleCancelPhrase.
                      if (!section) onClose();
                    }}
                  >
                    {t('settings.cancel_change_confirm')}
                  </Button>
                </>
              }
            />
          </Modal>
          <RecoveryKitBackup
            title={t('settings.change_phrase_new_title')}
            description={t('settings.change_phrase_success')}
            banner={
              <>
                {sessionBanner}
                {rearmBlockedNotice}
              </>
            }
            passphrase={newRecoveryPhrase}
            parentOrigin={null}
            onConfirm={handleConfirmPhraseBackup}
            confirmLabel={t('settings.change_phrase_confirm_saved')}
            busyLabel={t('settings.change_phrase_applying')}
            isBusy={isChangingPhrase}
            error={changeError}
          />
        </>
      );
    }

    if (changePhraseStep === 'done') {
      return (
        <Screen
          illustration="shield-check"
          title={t('settings.change_phrase_done_title')}
          description={t('settings.change_phrase_committed')}
          actions={<Button onClick={leaveView}>{t('settings.done')}</Button>}
        />
      );
    }

    return (
      <Screen
        back={backToHome}
        illustration="shield-gear"
        title={t('settings.change_phrase')}
        description={
          <>
            <p>{t('settings.change_phrase_warning')}</p>
            {/* There is only ONE flow: this rewrite replaces the owner's phrase
                AND, in the same server write, burns every emergency phrase a
                contact obtained and re-arms a fresh dormant one. The user never
                goes anywhere emergency-specific, so the screen has to say what is
                about to happen to their contacts. */}
            {liveEmergencyPhrases.length > 0 && (
              <p>
                {t('settings.change_phrase_emergency_note', {
                  names: liveEmergencyPhrases.join(', '),
                  count: liveEmergencyPhrases.length,
                })}
              </p>
            )}
          </>
        }
        banner={
          <>
            {sessionBanner}
            {changeError && <Notice type={VariantType.ERROR}>{changeError}</Notice>}
            {rearmBlockedNotice}
          </>
        }
        actions={
          <>
            <Button onClick={handleGeneratePhrase} disabled={isChangingPhrase || rearmBlocked !== null}>
              {isChangingPhrase ? t('settings.changing_phrase') : t('settings.change_phrase_continue')}
            </Button>
            <Button variant="bordered" color="neutral" onClick={handleCancelPhrase} disabled={isChangingPhrase}>
              {t('settings.change_phrase_cancel')}
            </Button>
          </>
        }
      />
    );
  }

  // ---------------------------------------------------------------------------
  // The home: the status of this device, then every flow.
  // ---------------------------------------------------------------------------
  const status = !keysExist ? (
    <StatusBanner
      tone="neutral"
      icon={<ShieldOff aria-hidden size={24} />}
      label={t('settings.status_not_set_up')}
      action={
        onSetUp && (
          <Button size="nano" onClick={onSetUp}>
            {t('settings.set_up')}
          </Button>
        )
      }
    />
  ) : outOfSync ? (
    <StatusBanner
      tone="warning"
      icon={<ShieldAlert aria-hidden size={24} />}
      label={remoteStatus === 'remote-disabled' ? t('settings.status_off_for_account') : t('settings.status_needs_attention')}
      action={
        <Button size="nano" variant="secondary" color="warning" onClick={() => setView('manage')}>
          {remoteStatus === 'remote-disabled' ? t('settings.review_options') : t('settings.review')}
        </Button>
      }
    />
  ) : (
    <StatusBanner
      tone="success"
      icon={<ShieldCheck aria-hidden size={24} />}
      label={t('settings.status_active')}
      action={
        <Button size="nano" variant="secondary" color="success" onClick={() => setView('manage')}>
          {t('settings.manage')}
        </Button>
      }
    />
  );

  return (
    <Screen title={t('settings.title')} description={t('settings.subtitle')} banner={sessionBanner}>
      {status}

      {syncIntegrityFailed && <SyncIntegrityAlert onRetry={handleRecheckSync} isRetrying={isRecheckingSync} />}

      {liveEmergencyPhrases.length > 0 && (
        <Notice type={VariantType.WARNING}>
          {t('settings.emergency_phrase_live', { names: liveEmergencyPhrases.join(', '), count: liveEmergencyPhrases.length })}
        </Notice>
      )}

      {keysExist && !outOfSync && (
        <>
          <div className={styles.section}>
            <p className={styles.sectionTitle}>{t('settings.group_settings')}</p>
            {onOpenDeviceApproval && (
              <SettingsRow
                title={t('settings.add_device_title')}
                description={t('settings.add_device_description')}
                action={
                  <Button size="nano" variant="bordered" icon={<PhoneDesktop aria-hidden size={16} />} onClick={onOpenDeviceApproval}>
                    {t('settings.add_device')}
                  </Button>
                }
              />
            )}
            <SettingsRow
              title={t('settings.verification_code_title')}
              description={t('settings.verification_code_row')}
              action={
                <Button size="nano" variant="bordered" icon={<Eye aria-hidden size={16} />} onClick={() => setView('verification-code')}>
                  {t('settings.show_code')}
                </Button>
              }
            />
            {onOpenCustodian && council.custodian && (
              <SettingsRow
                title={t('council.custodian_row_title')}
                description={council.pending > 0 ? t('council.custodian_row_pending', { count: council.pending }) : t('council.custodian_row')}
                action={
                  <Button size="nano" variant="bordered" color={council.pending > 0 ? 'warning' : 'neutral'} onClick={onOpenCustodian}>
                    {t('council.custodian_open')}
                  </Button>
                }
              />
            )}
          </div>

          <div className={styles.section}>
            <p className={styles.sectionTitle}>{t('settings.group_recovery')}</p>
            <SettingsRow
              title={t('settings.recovery_phrase_title')}
              description={t('settings.recovery_phrase_row')}
              action={
                <Button size="nano" variant="bordered" color="neutral" onClick={openChangePhrase}>
                  {t('settings.change_phrase')}
                </Button>
              }
            />
            {onOpenEmergencyAccess && (
              <SettingsRow
                title={t('settings.trusted_contacts_title')}
                description={t('settings.trusted_contacts_row')}
                action={
                  <Button size="nano" variant="bordered" color="neutral" onClick={onOpenEmergencyAccess}>
                    {t('settings.manage_trusted_contacts')}
                  </Button>
                }
              />
            )}
            {onOpenRecoveryCouncil && council.covered && (
              <SettingsRow
                title={t('council.row_title')}
                description={t('council.row_description')}
                action={
                  <Button size="nano" variant="bordered" color="neutral" onClick={onOpenRecoveryCouncil}>
                    {t('council.row_open')}
                  </Button>
                }
              />
            )}
          </div>
        </>
      )}
    </Screen>
  );
}
