import { Alert, Button, Checkbox, Modal, ModalSize, Radio, RadioGroup, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { computeKeyFingerprint, formatFingerprint } from '@encryption/src/crypto/fingerprint';
import { mnemonicLanguageForLocale } from '@encryption/src/crypto/mnemonic';
import { MSG_VAULT_DESTROY_KEYS } from '@encryption/src/shared/constants';
import type { VaultKeyringWire } from '@encryption/src/shared/schemas/vault';
import type { UserInfo } from '@encryption/src/ui/App';
import { fetchTrustedContacts } from '@encryption/src/ui/api/emergency-client';
import {
  deletePublicKeys,
  fetchNextKeyVersion,
  fetchPublicKeys,
  registerKeyComplete,
  registerKeyInit,
} from '@encryption/src/ui/api/public-keys-client';
import { SessionExpiredError, withFreshToken } from '@encryption/src/ui/auth/session-expired';
import { RecoveryKitBackup } from '@encryption/src/ui/components/RecoveryKitBackup';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
import { UntrustedRearmError, grantedRearmRows } from '@encryption/src/ui/components/emergency-access-logic';
import { Chip, FingerprintBoxes, IdentityCard } from '@encryption/src/ui/components/layout/IdentityCard';
import { Icon, LoadingScreen, Screen } from '@encryption/src/ui/components/layout/Screen';
import { useCloseGuard } from '@encryption/src/ui/hooks/useCloseRequest';
import { useKeyringCommit } from '@encryption/src/ui/hooks/useKeyringCommit';
import { useSessionExpired } from '@encryption/src/ui/hooks/useSessionExpired';
import { useUnsavedPhraseGuard } from '@encryption/src/ui/hooks/useUnsavedPhraseGuard';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

interface EncryptionSettingsProps {
  userInfo?: UserInfo | null;
  userId?: string | null;
  getToken: () => Promise<string | null>;
  onClose: () => void;
  onKeysDestroyed: () => void;
  onOpenDeviceApproval?: () => void;
  onOpenEmergencyAccess?: () => void;
  onReconnect?: () => void;
  isAuthenticating?: boolean;
  currentAccessToken?: string | null;
}

export function EncryptionSettings({
  userInfo = null,
  userId = null,
  getToken,
  onClose,
  onKeysDestroyed,
  onOpenDeviceApproval,
  onOpenEmergencyAccess,
  onReconnect,
  isAuthenticating = false,
  currentAccessToken = null,
}: EncryptionSettingsProps) {
  const { t, i18n } = useTranslation('common');
  const { isReady, hasKeys, getPublicKey, request, changeRecoveryPhrase, signKeyRegistration, respondToKeyChallenge } = useEncryptionContext();

  // Stepped, deferred-commit change-recovery-phrase flow:
  //   idle -> warning (existing backups will be invalidated) -> backup (full
  //   Recovery Kit UX) -> commit on confirm. The re-wrapped keyring is held
  //   locally and only sent to the server (invalidating the old phrase) once the
  //   user confirms they saved the new one, so cancelling leaves everything intact.
  const [changePhraseStep, setChangePhraseStep] = useState<'idle' | 'warning' | 'backup' | 'done'>('idle');
  const [pendingKeyring, setPendingKeyring] = useState<VaultKeyringWire | null>(null);
  const [newRecoveryPhrase, setNewRecoveryPhrase] = useState<string | null>(null);
  const [isChangingPhrase, setIsChangingPhrase] = useState(false);
  const [changeError, setChangeError] = useState<string | null>(null);
  // Session-expired banner state (mirrors the onboarding modal). The commit step
  // can now run minutes after generating (the user is saving their phrase), so the
  // OIDC token may have lapsed by then; show the reconnect banner instead of a raw
  // error and let the user retry once reconnected (the pending keyring is kept).
  const { sessionExpired, markSessionExpired } = useSessionExpired(currentAccessToken, isAuthenticating);

  // Generate the new phrase + re-wrap the keyring LOCALLY (no server call yet).
  const handleGeneratePhrase = useCallback(async () => {
    setIsChangingPhrase(true);
    setChangeError(null);

    try {
      const lang = mnemonicLanguageForLocale(i18n.language);
      const { recoveryPhrase, keyring } = await changeRecoveryPhrase(lang);
      setPendingKeyring(keyring);
      setNewRecoveryPhrase(recoveryPhrase);
      setChangePhraseStep('backup');
    } catch (err) {
      setChangeError((err as Error).message);
    } finally {
      setIsChangingPhrase(false);
    }
  }, [changeRecoveryPhrase, i18n.language]);

  // Commit the new keyring to the server. This is the moment the OLD phrase (and
  // all its backups) stops working, so it runs only after the user confirms.
  // Goes through the shared keyring-commit flow: while a recovery is granted the
  // server rejects the rewrite unless the granted escrows are burned + re-armed,
  // so a routine phrase change carries the mandatory re-arms too.
  const { commitKeyring, revokeContacts } = useKeyringCommit(getToken);
  const [rearmBlocked, setRearmBlocked] = useState<Array<{ id: string; email: string }> | null>(null);

  const handleConfirmPhraseBackup = useCallback(async () => {
    if (!pendingKeyring) return;

    setIsChangingPhrase(true);
    setChangeError(null);
    setRearmBlocked(null);

    try {
      await commitKeyring(pendingKeyring, mnemonicLanguageForLocale(i18n.language));
      setPendingKeyring(null);
      setNewRecoveryPhrase(null);
      // Show the confirmation in context, on its own screen, instead of dropping
      // back to the settings home with a success banner lingering above the button.
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
  // built: revoke exactly those relationships (user-approved) and retry.
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
    await handleConfirmPhraseBackup();
  }, [rearmBlocked, revokeContacts, markSessionExpired, handleConfirmPhraseBackup]);

  // Back out before committing: nothing was sent to the server, so just drop the
  // unsaved phrase and re-wrapped keyring. The current phrase keeps working.
  const handleCancelPhrase = useCallback(() => {
    setPendingKeyring(null);
    setNewRecoveryPhrase(null);
    setChangeError(null);
    setRearmBlocked(null);
    setChangePhraseStep('idle');
  }, []);

  // Divergence between this device's identity and the server directory. The
  // settings screen otherwise shows only the LOCAL key, so a disable/rotation
  // performed from another device would go unnoticed here.
  // remote-disabled: an identity was registered then disabled elsewhere (re-enable
  // is legitimate). remote-never: no identity was EVER registered for this user
  // (an orphaned local vault) — re-enabling would push a directory entry with no
  // vault, so we only offer a clean re-onboard.
  const [remoteStatus, setRemoteStatus] = useState<'checking' | 'in-sync' | 'remote-disabled' | 'remote-never' | 'remote-diverged'>('checking');
  const [remoteFingerprint, setRemoteFingerprint] = useState<string | null>(null);
  const [reconciling, setReconciling] = useState(false);
  const [reconcileError, setReconcileError] = useState<string | null>(null);

  // Reconciliation choice A — bring THIS device's identity back as the active one.
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
      await withFreshToken(getToken, async (token) => {
        const next = await fetchNextKeyVersion(token);
        const reg = await signKeyRegistration(next.next_version, Date.now());
        const init = await registerKeyInit(token, {
          user_id: userId,
          encryption_public_key: reg.encryptionPublicKey,
          signature_public_key: reg.signaturePublicKey,
          version: reg.version,
          created_at_millis: reg.createdAtMillis,
          key_binding_signature: reg.keyBindingSignature,
        });
        const { response, challengeSignature } = await respondToKeyChallenge(init.challenge_id, init.ciphertext);

        await registerKeyComplete(token, { challenge_id: init.challenge_id, response, challenge_signature: challengeSignature });
      });
      setRemoteStatus('in-sync');
    } catch (err) {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else setReconcileError((err as Error).message);
    } finally {
      setReconciling(false);
    }
  }, [userId, getToken, signKeyRegistration, respondToKeyChallenge, markSessionExpired]);

  // Reconciliation choice B — adopt the SERVER's identity instead. This device's
  // local keys are the wrong identity, so discard them and re-acquire the active
  // one from a device that holds it (device approval) or its recovery phrase.
  const handleAdoptServerIdentity = useCallback(async () => {
    if (!window.confirm(t('settings.reconcile_adopt_confirm'))) return;

    try {
      await request(MSG_VAULT_DESTROY_KEYS);
    } catch {
      // Best-effort: proceed to re-acquire regardless.
    }

    if (onOpenDeviceApproval) onOpenDeviceApproval();
    else onKeysDestroyed();
  }, [request, onOpenDeviceApproval, onKeysDestroyed, t]);

  // Warn on tab reload/close while the new (un-committed, unsaved) phrase is shown.
  useUnsavedPhraseGuard(changePhraseStep === 'backup' && !isChangingPhrase);

  const [keysExist, setKeysExist] = useState<boolean | null>(null);
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [showDangerZone, setShowDangerZone] = useState(false);
  const [confirmDataLoss, setConfirmDataLoss] = useState(false);
  const [alsoDisableServer, setAlsoDisableServer] = useState(false);
  const [confirmFingerprint, setConfirmFingerprint] = useState('');
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

    withFreshToken(getToken, (token) => fetchTrustedContacts(token))
      .then(({ contacts }) => {
        if (!cancelled) setLiveEmergencyPhrases(grantedRearmRows(contacts, Date.now()).map((row) => row.granteeEmail));
      })
      .catch(() => {
        // Advisory banner only: a failed fetch must not break the settings screen.
      });

    return () => {
      cancelled = true;
    };
  }, [keysExist, getToken, changePhraseStep]);

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
        // Auth may not be set yet — will retry when isReady changes
      });
  }, [isReady, hasKeys, getPublicKey]);

  // Compare the local identity (signature fingerprint) against the server's
  // currently ACTIVE registration. Only identity-level divergence matters here:
  //   - remote-disabled: a key was registered then disabled (re-enable is valid);
  //   - remote-never: no key was ever registered (orphaned local vault);
  //   - remote-diverged: the active key belongs to a different identity than
  //     this device (another device rotated/recreated it).
  // A network error is treated as in-sync so we never raise a false alarm.

  // Re-enter the checking state when the identity under comparison changes.Done while rendering rather than from the effect:
  // Not done in the `useEffect` to have `useState` outside as expected by eslint
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
          // the disabled path — the server guard still refuses an illegitimate
          // re-register.
          let everRegistered = true;
          try {
            const next = await withFreshToken(getToken, (token) => fetchNextKeyVersion(token));
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
  }, [fingerprint, userId, getToken]);

  const fingerprintMatch = !!fingerprint && confirmFingerprint.replace(/\s/g, '') === fingerprint;
  const canDelete = confirmDataLoss && fingerprintMatch;

  const handleDeleteKeys = useCallback(async () => {
    if (!canDelete) return;

    setIsPending(true);
    setError(null);

    try {
      // Disable the public key in the directory FIRST (if requested), so others
      // stop using a key this user can no longer decrypt with. This is a soft,
      // reversible disable — NOT a destructive vault wipe (a stolen JWT must never
      // be able to destroy the vault; only reading unreadable ciphertext is
      // acceptable). withFreshToken (never a raw getToken) guarantees a valid
      // token or throws SessionExpiredError: a lapsed session must surface the
      // reconnect banner and ABORT here, never silently skip the disable and then
      // wipe local keys, which would leave this device empty while the server key
      // stays active (and the next screen wrongly reads "existing configuration").
      if (alsoDisableServer) {
        await withFreshToken(getToken, (token) => deletePublicKeys(token));
      }

      // Only now remove this device's local keys + vault cache. The server vault
      // is left intact so other devices and the recovery phrase keep working.
      await request(MSG_VAULT_DESTROY_KEYS);
      setKeysExist(false);
      setFingerprint(null);
      setShowDangerZone(false);
      onKeysDestroyed();
    } catch (err) {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else setError((err as Error).message);
    } finally {
      setIsPending(false);
    }
  }, [canDelete, alsoDisableServer, getToken, request, onKeysDestroyed, markSessionExpired]);

  const resetDangerZone = useCallback(() => {
    setShowDangerZone(false);
    setConfirmDataLoss(false);
    setAlsoDisableServer(false);
    setConfirmFingerprint('');
    setError(null);
  }, []);

  // The product's close control while the new phrase is unsaved: dropping it is
  // harmless (nothing was sent yet), but make the choice explicit.
  const [cancelPrompt, setCancelPrompt] = useState(false);
  useCloseGuard(changePhraseStep === 'backup' && !isChangingPhrase, () => setCancelPrompt(true));

  const displayName = userInfo?.name || userInfo?.email || t('settings.you');
  const displayEmail = userInfo?.name ? userInfo.email : null;

  const sessionBanner = sessionExpired && onReconnect && <SessionExpiredAlert onReconnect={onReconnect} isAuthenticating={isAuthenticating} />;

  if (keysExist === null) {
    return <LoadingScreen label={t('settings.loading')} />;
  }

  // Hard-gate: when this device's identity disagrees with the server directory,
  // the user must choose how to reconcile BEFORE anything else, so local and
  // remote stop disagreeing. Shown as its own full view, replacing settings.
  // (Detection is async, so settings may render for a moment first — that is
  // deliberate; we never block the whole screen on a vault/network round-trip.)
  if (keysExist && !showDangerZone && remoteStatus !== 'checking' && remoteStatus !== 'in-sync') {
    const banner = (
      <>
        {sessionBanner}
        {reconcileError && <Alert type={VariantType.ERROR}>{reconcileError}</Alert>}
      </>
    );
    const removeLocalButton = (
      <Button variant="tertiary" color="error" onClick={() => setShowDangerZone(true)} disabled={reconciling}>
        {t('settings.reconcile_delete_local')}
      </Button>
    );

    // remote-never has no legitimate re-enable: the identity was never on the
    // server, so the only coherent action is to remove the orphaned local keys
    // and onboard from scratch.
    if (remoteStatus === 'remote-never') {
      return (
        <Screen
          illustration="shield-x"
          title={t('settings.remote_never_title')}
          description={
            <>
              <p>{t('settings.remote_never_warning')}</p>
              <p>{t('settings.remote_never_hint')}</p>
            </>
          }
          banner={banner}
          actions={
            <Button onClick={() => setShowDangerZone(true)} disabled={reconciling}>
              {t('settings.reconcile_onboard_fresh')}
            </Button>
          }
        />
      );
    }

    if (remoteStatus === 'remote-disabled') {
      return (
        <Screen
          illustration="shield-x"
          title={t('settings.remote_disabled_title')}
          description={
            <>
              <p>{t('settings.remote_disabled_warning')}</p>
              <p>{t('settings.reconcile_reenable_hint')}</p>
            </>
          }
          banner={banner}
          actions={
            <>
              <Button variant="secondary" onClick={handleReactivateIdentity} disabled={reconciling}>
                {reconciling ? t('settings.reconcile_working') : t('settings.reconcile_reenable')}
              </Button>
              {removeLocalButton}
            </>
          }
        />
      );
    }

    return (
      <Screen
        title={t('settings.title')}
        banner={banner}
        actions={
          <>
            <Button onClick={handleAdoptServerIdentity} disabled={reconciling}>
              {t('settings.reconcile_adopt_server')}
            </Button>
            <Button variant="secondary" onClick={handleReactivateIdentity} disabled={reconciling}>
              {reconciling ? t('settings.reconcile_working') : t('settings.reconcile_keep_local')}
            </Button>
            {removeLocalButton}
          </>
        }
      >
        {fingerprint && (
          <IdentityCard
            name={displayName}
            secondary={displayEmail}
            fingerprint={fingerprint}
            tone="warning"
            aside={
              <Chip tone="warning" icon="warning">
                {t('settings.key_mismatch')}
              </Chip>
            }
          />
        )}
        <p className="enc-hint">{t('settings.remote_diverged_warning')}</p>
        {remoteFingerprint && (
          <div>
            <p className="enc-label">{t('settings.remote_server')}</p>
            <FingerprintBoxes fingerprint={remoteFingerprint} />
          </div>
        )}
        <p className="enc-hint">{t('settings.reconcile_diverged_hint')}</p>
      </Screen>
    );
  }

  // The backup step takes over the whole settings view (like the onboarding
  // backup screen), rather than sitting inline or in a modal. The confirm-before
  // warning is the only part shown as a modal (below).
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
                <Button onClick={() => setCancelPrompt(false)}>{t('onboarding.btn_go_back')}</Button>
                <Button
                  variant="bordered"
                  color="error"
                  onClick={() => {
                    setCancelPrompt(false);
                    handleCancelPhrase();
                    onClose();
                  }}
                >
                  {t('onboarding.btn_close_anyway')}
                </Button>
              </>
            }
          />
        </Modal>
        <RecoveryKitBackup
          illustration="shield-check"
          title={t('settings.change_phrase_new_title')}
          description={t('settings.change_phrase_success')}
          banner={
            <>
              {sessionBanner}
              {rearmBlocked && (
                <Alert type={VariantType.WARNING}>
                  <div className="enc-alert-stack">
                    <span>{t('emergency.rearm_blocked', { emails: rearmBlocked.map((contact) => contact.email).join(', ') })}</span>
                    <div>
                      <Button size="small" color="error" onClick={handleRevokeBlockedAndRetry} disabled={isChangingPhrase}>
                        {t('emergency.rearm_revoke_retry')}
                      </Button>
                    </div>
                  </div>
                </Alert>
              )}
            </>
          }
          passphrase={newRecoveryPhrase}
          parentOrigin={null}
          onConfirm={handleConfirmPhraseBackup}
          confirmLabel={t('settings.change_phrase_confirm_saved')}
          busyLabel={t('settings.change_phrase_applying')}
          isBusy={isChangingPhrase}
          error={changeError}
          onCancel={handleCancelPhrase}
          cancelLabel={t('settings.change_phrase_cancel')}
        />
      </>
    );
  }

  // Confirmation shown right after the change commits, as its own view, then
  // dismissed back to the settings home (no lingering banner there).
  if (changePhraseStep === 'done') {
    return (
      <Screen
        illustration="shield-check"
        title={t('settings.change_phrase')}
        description={t('settings.change_phrase_committed')}
        actions={<Button onClick={() => setChangePhraseStep('idle')}>{t('settings.change_phrase_done')}</Button>}
      />
    );
  }

  // The "remove encryption" flow takes over the whole view rather than sitting
  // inside a box on the settings home, since it is a destructive action.
  if (showDangerZone) {
    return (
      <Screen
        title={t('settings.delete_title')}
        banner={
          <>
            {sessionBanner}
            {error && <Alert type={VariantType.ERROR}>{error}</Alert>}
          </>
        }
        actionsLayout="row"
        actions={
          <>
            <Button variant="bordered" color="neutral" onClick={resetDangerZone} disabled={isPending}>
              {t('onboarding.btn_cancel')}
            </Button>
            <Button color="error" onClick={handleDeleteKeys} disabled={isPending || !canDelete}>
              {isPending ? t('settings.deleting') : t('settings.delete_button')}
            </Button>
          </>
        }
      >
        <RadioGroup>
          <Radio
            name="delete-scope"
            label={t('settings.delete_scope_device')}
            text={t('settings.delete_scope_device_hint')}
            checked={!alsoDisableServer}
            onChange={() => setAlsoDisableServer(false)}
          />
          <Radio
            name="delete-scope"
            label={t('settings.delete_scope_account')}
            text={t('settings.delete_scope_account_hint')}
            checked={alsoDisableServer}
            onChange={() => setAlsoDisableServer(true)}
          />
        </RadioGroup>

        <Alert type={VariantType.ERROR}>
          <div className="enc-alert-stack">
            <span>{alsoDisableServer ? t('settings.disable_server_warning') : t('settings.delete_warning_backup')}</span>
            <Checkbox label={t('onboarding.i_understand')} checked={confirmDataLoss} onChange={() => setConfirmDataLoss(!confirmDataLoss)} />
          </div>
        </Alert>

        <div>
          <label className="enc-label" htmlFor="settings-confirm-fingerprint">
            {t('settings.confirm_fingerprint_prompt')}
          </label>
          {fingerprint && (
            <div style={{ marginBottom: 8 }}>
              <FingerprintBoxes fingerprint={fingerprint} />
            </div>
          )}
          <input
            id="settings-confirm-fingerprint"
            type="text"
            inputMode="numeric"
            value={confirmFingerprint}
            onChange={(e) => setConfirmFingerprint(e.target.value)}
            placeholder={fingerprint ? formatFingerprint(fingerprint) : ''}
            className={fingerprintMatch ? 'enc-input enc-input--mono enc-input--valid' : 'enc-input enc-input--mono'}
          />
        </div>
      </Screen>
    );
  }

  return (
    <>
      {/* Only the confirm-before warning is a modal; on Continue the backup
          step takes over the whole view (handled by the early return above). */}
      <Modal
        isOpen={changePhraseStep === 'warning'}
        onClose={isChangingPhrase ? () => undefined : handleCancelPhrase}
        closeOnClickOutside={false}
        size={ModalSize.SMALL}
        aria-label={t('settings.change_phrase')}
      >
        <Screen
          title={t('settings.change_phrase')}
          description={
            <>
              <p>{t('settings.change_phrase_warning')}</p>
              {/* There is only ONE flow: this rewrite replaces the owner's phrase
                  AND, in the same server write, burns every emergency phrase a
                  contact obtained and re-arms a fresh dormant one. The user never
                  goes anywhere emergency-specific, so the modal has to say what is
                  about to happen to their contacts rather than leave them guessing
                  which phrase this is about. */}
              {liveEmergencyPhrases.length > 0 && (
                <p>
                  {t('settings.change_phrase_emergency_note', {
                    emails: liveEmergencyPhrases.join(', '),
                    count: liveEmergencyPhrases.length,
                  })}
                </p>
              )}
            </>
          }
          banner={changeError && <Alert type={VariantType.ERROR}>{changeError}</Alert>}
          actions={
            <>
              <Button onClick={handleGeneratePhrase} disabled={isChangingPhrase}>
                {isChangingPhrase ? t('settings.changing_phrase') : t('settings.change_phrase_continue')}
              </Button>
              <Button variant="bordered" color="neutral" onClick={handleCancelPhrase} disabled={isChangingPhrase}>
                {t('settings.change_phrase_cancel')}
              </Button>
            </>
          }
        />
      </Modal>

      <Screen
        title={t('settings.title')}
        banner={sessionBanner}
        actions={
          keysExist && (
            <>
              {onOpenDeviceApproval && (
                <Button variant="secondary" onClick={onOpenDeviceApproval} icon={<Icon name="laptop" />}>
                  {t('settings.add_device')}
                </Button>
              )}
              {onOpenEmergencyAccess && (
                <Button variant="secondary" onClick={onOpenEmergencyAccess} icon={<Icon name="group" />}>
                  {t('emergency.settings_entry')}
                </Button>
              )}
              <Button
                variant="tertiary"
                onClick={() => {
                  setChangeError(null);
                  setChangePhraseStep('warning');
                }}
                icon={<Icon name="key" />}
              >
                {t('settings.change_phrase')}
              </Button>
              <Button variant="tertiary" color="error" onClick={() => setShowDangerZone(true)}>
                {t('settings.show_danger_zone')}
              </Button>
            </>
          )
        }
      >
        {!keysExist && <Alert type={VariantType.INFO}>{t('settings.no_keys')}</Alert>}

        {keysExist && fingerprint && (
          <>
            <IdentityCard name={displayName} secondary={displayEmail} fingerprint={fingerprint} />
            <p className="enc-hint">{t('settings.safety_fingerprint_hint')}</p>
          </>
        )}

        {liveEmergencyPhrases.length > 0 && changePhraseStep === 'idle' && (
          <Alert type={VariantType.WARNING}>
            {t('settings.emergency_phrase_live', { emails: liveEmergencyPhrases.join(', '), count: liveEmergencyPhrases.length })}
          </Alert>
        )}
      </Screen>
    </>
  );
}
