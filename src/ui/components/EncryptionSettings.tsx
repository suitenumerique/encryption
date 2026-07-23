import { Alert, Button, Checkbox, Loader, Modal, ModalSize, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { computeKeyFingerprint, formatFingerprint } from '@encryption/src/crypto/fingerprint';
import { mnemonicLanguageForLocale } from '@encryption/src/crypto/mnemonic';
import { MSG_VAULT_DESTROY_KEYS, MSG_VAULT_SIGN_REQUEST } from '@encryption/src/shared/constants';
import type { VaultKeyringWire } from '@encryption/src/shared/schemas/vault';
import type { UserInfo } from '@encryption/src/ui/App';
import { apiDefaults, authHeaders, signedHeaders } from '@encryption/src/ui/api/client';
import {
  deleteApiPublicKeys,
  getApiPublicKeys,
  getApiPublicKeysNext,
  postApiPublicKeysRegisterComplete,
  postApiPublicKeysRegisterInit,
  putApiVaultKeyring,
} from '@encryption/src/ui/api/generated/sdk.gen';
import { SessionExpiredError, withFreshToken } from '@encryption/src/ui/auth/session-expired';
import { FingerprintDisplay } from '@encryption/src/ui/components/FingerprintDisplay';
import { RecoveryKitBackup } from '@encryption/src/ui/components/RecoveryKitBackup';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
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
  const handleConfirmPhraseBackup = useCallback(async () => {
    if (!pendingKeyring) return;

    setIsChangingPhrase(true);
    setChangeError(null);

    try {
      // Covered route: sign the EXACT body we will send (same serialization the
      // request helper uses), so the proof's body digest matches, then attach it.
      const body = JSON.stringify(pendingKeyring);
      const { signature } = (await request(MSG_VAULT_SIGN_REQUEST, { method: 'PUT', path: '/api/vault/keyring', body })) as { signature: string };

      await withFreshToken(getToken, (token) =>
        putApiVaultKeyring({ ...apiDefaults, headers: signedHeaders(token, signature), body: pendingKeyring })
      );
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
      } else {
        setChangeError((err as Error).message);
      }
    } finally {
      setIsChangingPhrase(false);
    }
  }, [pendingKeyring, getToken, request, markSessionExpired]);

  // Back out before committing: nothing was sent to the server, so just drop the
  // unsaved phrase and re-wrapped keyring. The current phrase keeps working.
  const handleCancelPhrase = useCallback(() => {
    setPendingKeyring(null);
    setNewRecoveryPhrase(null);
    setChangeError(null);
    setChangePhraseStep('idle');
  }, []);

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
        const next = await getApiPublicKeysNext({ ...apiDefaults, headers: authHeaders(token) });
        const reg = await signKeyRegistration(next.data.next_version, Date.now());
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
        const { response, challengeSignature } = await respondToKeyChallenge(init.data.challenge_id, init.data.ciphertext);

        await postApiPublicKeysRegisterComplete({
          ...apiDefaults,
          headers: authHeaders(token),
          body: { challenge_id: init.data.challenge_id, response, challenge_signature: challengeSignature },
        });
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
  // Divergence between this device's identity and the server directory. The
  // settings screen otherwise shows only the LOCAL key, so a disable/rotation
  // performed from another device would go unnoticed here.
  // remote-disabled: an identity was registered then disabled elsewhere (re-enable
  // is legitimate). remote-never: no identity was EVER registered for this user
  // (an orphaned local vault) — re-enabling would push a directory entry with no
  // vault, so we only offer a clean re-onboard.
  const [remoteStatus, setRemoteStatus] = useState<'checking' | 'in-sync' | 'remote-disabled' | 'remote-never' | 'remote-diverged'>('checking');
  const [remoteFingerprint, setRemoteFingerprint] = useState<string | null>(null);
  const [showDangerZone, setShowDangerZone] = useState(false);
  // The safety fingerprint is revealed on demand, not shown by default.
  const [showFingerprint, setShowFingerprint] = useState(false);
  const [confirmDataLoss, setConfirmDataLoss] = useState(false);
  const [alsoDisableServer, setAlsoDisableServer] = useState(false);
  const [confirmServerDisable, setConfirmServerDisable] = useState(false);
  const [confirmFingerprint, setConfirmFingerprint] = useState('');
  const [isPending, setIsPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
  useEffect(() => {
    if (!fingerprint || !userId) return;

    let cancelled = false;
    setRemoteStatus('checking');
    getApiPublicKeys({ ...apiDefaults, query: { user_ids: [userId] } })
      .then(async ({ data }) => {
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
            const next = await withFreshToken(getToken, (token) => getApiPublicKeysNext({ ...apiDefaults, headers: authHeaders(token) }));
            everRegistered = next.data.next_generation > 1;
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

  const fingerprintMatch = !!fingerprint && confirmFingerprint.toLowerCase().replace(/\s/g, '') === fingerprint;
  const canDelete = confirmDataLoss && (!alsoDisableServer || confirmServerDisable) && fingerprintMatch;

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
        await withFreshToken(getToken, (token) => deleteApiPublicKeys({ ...apiDefaults, headers: authHeaders(token) }));
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
    setConfirmServerDisable(false);
    setConfirmFingerprint('');
    setError(null);
  }, []);

  if (keysExist === null) {
    return (
      <div
        style={{
          padding: 'var(--c--globals--spacings--4, 16px)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <Loader />
        <p>{t('settings.loading')}</p>
      </div>
    );
  }

  // Hard-gate: when this device's identity disagrees with the server directory,
  // the user must choose how to reconcile BEFORE anything else, so local and
  // remote stop disagreeing. Shown as its own full view, replacing settings.
  // (Detection is async, so settings may render for a moment first — that is
  // deliberate; we never block the whole screen on a vault/network round-trip.)
  if (keysExist && !showDangerZone && remoteStatus !== 'checking' && remoteStatus !== 'in-sync') {
    // remote-never has no legitimate re-enable: the identity was never on the
    // server, so the only coherent action is to remove the orphaned local keys
    // and onboard from scratch.
    const canReenable = remoteStatus !== 'remote-never';
    const warning =
      remoteStatus === 'remote-never'
        ? t('settings.remote_never_warning')
        : remoteStatus === 'remote-disabled'
          ? t('settings.remote_disabled_warning')
          : t('settings.remote_diverged_warning');
    const hint =
      remoteStatus === 'remote-never'
        ? t('settings.remote_never_hint')
        : remoteStatus === 'remote-disabled'
          ? t('settings.reconcile_reenable_hint')
          : t('settings.reconcile_diverged_hint');

    return (
      <div style={{ padding: 'var(--c--globals--spacings--4, 16px)' }}>
        <h2>{t('settings.reconcile_title')}</h2>
        {sessionExpired && onReconnect && (
          <div style={{ marginBottom: 8 }}>
            <SessionExpiredAlert onReconnect={onReconnect} isAuthenticating={isAuthenticating} />
          </div>
        )}
        <Alert type={VariantType.WARNING}>{warning}</Alert>

        {remoteStatus === 'remote-diverged' && fingerprint && remoteFingerprint && (
          <div style={{ margin: '12px 0', fontSize: 13, display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div>
              <p style={{ margin: '0 0 4px', fontWeight: 700 }}>{t('settings.remote_this_device')}</p>
              <FingerprintDisplay fingerprint={fingerprint} style={{ fontSize: 14 }} />
            </div>
            <div>
              <p style={{ margin: '0 0 4px', fontWeight: 700 }}>{t('settings.remote_server')}</p>
              <FingerprintDisplay fingerprint={remoteFingerprint} style={{ fontSize: 14 }} />
            </div>
          </div>
        )}

        {reconcileError && (
          <div style={{ marginTop: 8 }}>
            <Alert type={VariantType.ERROR}>{reconcileError}</Alert>
          </div>
        )}

        <p style={{ margin: '16px 0 8px', fontSize: 13, color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>{hint}</p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
          {canReenable && (
            <Button fullWidth onClick={handleReactivateIdentity} disabled={reconciling}>
              {reconciling
                ? t('settings.reconcile_working')
                : remoteStatus === 'remote-disabled'
                  ? t('settings.reconcile_reenable')
                  : t('settings.reconcile_keep_local')}
            </Button>
          )}
          {remoteStatus === 'remote-diverged' && (
            <Button variant="secondary" fullWidth onClick={handleAdoptServerIdentity} disabled={reconciling}>
              {t('settings.reconcile_adopt_server')}
            </Button>
          )}
          {/* Remove local keys. For remote-never this is the only path (onboard
              fresh); otherwise it is the fallback to reactivation. */}
          <Button variant={canReenable ? 'tertiary' : 'primary'} fullWidth onClick={() => setShowDangerZone(true)} disabled={reconciling}>
            {canReenable ? t('settings.reconcile_delete_local') : t('settings.reconcile_onboard_fresh')}
          </Button>
        </div>
      </div>
    );
  }

  // The backup step takes over the whole settings view (like the onboarding
  // backup screen), rather than sitting inline or in a modal. The confirm-before
  // warning is the only part shown as a modal (below).
  if (changePhraseStep === 'backup' && newRecoveryPhrase) {
    return (
      <div style={{ padding: 'var(--c--globals--spacings--4, 16px)' }}>
        <h2>{t('onboarding.title_backup')}</h2>
        {sessionExpired && onReconnect && (
          <div style={{ marginBottom: 8 }}>
            <SessionExpiredAlert onReconnect={onReconnect} isAuthenticating={isAuthenticating} />
          </div>
        )}
        <Alert type={VariantType.INFO}>{t('settings.change_phrase_success')}</Alert>
        <RecoveryKitBackup
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
      </div>
    );
  }

  // Confirmation shown right after the change commits, as its own view, then
  // dismissed back to the settings home (no lingering banner there).
  if (changePhraseStep === 'done') {
    return (
      <div style={{ padding: 'var(--c--globals--spacings--4, 16px)' }}>
        <h2>{t('settings.change_phrase')}</h2>
        <Alert type={VariantType.SUCCESS}>{t('settings.change_phrase_committed')}</Alert>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
          <Button onClick={() => setChangePhraseStep('idle')}>{t('settings.change_phrase_done')}</Button>
        </div>
      </div>
    );
  }

  // The "delete local keys" danger zone takes over the whole view rather than
  // sitting inside a box on the settings home, since it is a destructive action.
  if (showDangerZone) {
    return (
      <div style={{ padding: 'var(--c--globals--spacings--4, 16px)' }}>
        <h2 style={{ color: 'var(--c--globals--colors--error-500, #ce0500)' }}>{t('settings.delete_title')}</h2>

        <Alert type={VariantType.WARNING}>{t('settings.delete_warning_backup')}</Alert>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 16 }}>
          <Checkbox label={t('settings.confirm_data_loss')} checked={confirmDataLoss} onChange={() => setConfirmDataLoss(!confirmDataLoss)} />

          <div style={{ marginTop: 8, borderTop: '1px solid var(--c--contextuals--border--surface--primary, #ddd)', paddingTop: 12 }}>
            <Checkbox
              label={t('settings.also_disable_server')}
              checked={alsoDisableServer}
              onChange={() => {
                setAlsoDisableServer(!alsoDisableServer);
                setConfirmServerDisable(false);
              }}
            />
            {alsoDisableServer && (
              <div style={{ marginLeft: 24, marginTop: 8 }}>
                <Alert type={VariantType.ERROR}>{t('settings.disable_server_warning')}</Alert>
                <div style={{ marginTop: 8 }}>
                  <Checkbox
                    label={t('settings.confirm_server_disable')}
                    checked={confirmServerDisable}
                    onChange={() => setConfirmServerDisable(!confirmServerDisable)}
                  />
                </div>
              </div>
            )}
          </div>

          <div style={{ marginTop: 8, borderTop: '1px solid var(--c--contextuals--border--surface--primary, #ddd)', paddingTop: 12 }}>
            <p style={{ fontSize: 13, margin: '0 0 8px' }}>{t('settings.confirm_fingerprint_prompt')}</p>
            {fingerprint && (
              <div
                style={{
                  fontSize: 14,
                  padding: 'var(--c--globals--spacings--2, 8px)',
                  background: 'var(--c--contextuals--background--surface--secondary, #f5f5fe)',
                  borderRadius: 4,
                  marginBottom: 8,
                }}
              >
                <FingerprintDisplay fingerprint={fingerprint} style={{ fontSize: 14 }} />
              </div>
            )}
            <input
              type="text"
              value={confirmFingerprint}
              onChange={(e) => setConfirmFingerprint(e.target.value)}
              placeholder={fingerprint ? formatFingerprint(fingerprint) : ''}
              style={{
                width: '100%',
                boxSizing: 'border-box',
                fontFamily: 'monospace',
                fontSize: 14,
                letterSpacing: '0.05em',
                padding: 'var(--c--globals--spacings--2, 8px)',
                borderRadius: 4,
                border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
              }}
            />
          </div>
        </div>

        {error && (
          <div style={{ marginTop: 8 }}>
            <Alert type={VariantType.ERROR}>{error}</Alert>
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
          <Button variant="secondary" onClick={resetDangerZone}>
            {t('onboarding.btn_cancel')}
          </Button>
          <Button color="error" onClick={handleDeleteKeys} disabled={isPending || !canDelete}>
            {isPending ? t('settings.deleting') : t('settings.delete_button')}
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ padding: 'var(--c--globals--spacings--4, 16px)' }}>
      <h2>{t('settings.title')}</h2>

      {userInfo?.name && (
        <p style={{ color: 'var(--c--contextuals--content--surface--secondary, #666)', marginBottom: 'var(--c--globals--spacings--3, 12px)' }}>
          {userInfo.name}
          {userInfo.email ? ` (${userInfo.email})` : ''}
        </p>
      )}

      {!keysExist && (
        <div style={{ marginBottom: 'var(--c--globals--spacings--4, 16px)' }}>
          <Alert type={VariantType.INFO}>{t('settings.no_keys')}</Alert>
        </div>
      )}

      {keysExist && fingerprint && (
        <>
          {/* Safety fingerprint: an action button like the others. The digits and
              their explanation live in the modal, not inline. */}
          <div style={{ marginBottom: 'var(--c--globals--spacings--4, 16px)' }}>
            <Button variant="secondary" onClick={() => setShowFingerprint(true)}>
              {t('settings.reveal_fingerprint')}
            </Button>
          </div>

          <Modal isOpen={showFingerprint} onClose={() => setShowFingerprint(false)} size={ModalSize.MEDIUM} title={t('settings.fingerprint_label')}>
            <div style={{ paddingBottom: 'var(--c--globals--spacings--4, 16px)' }}>
              <div
                style={{
                  textAlign: 'center',
                  padding: 'var(--c--globals--spacings--3, 12px)',
                  background: 'var(--c--contextuals--background--surface--secondary, #f5f5fe)',
                  borderRadius: 4,
                }}
              >
                <FingerprintDisplay fingerprint={fingerprint} style={{ fontSize: 18, letterSpacing: '0.08em', lineHeight: 1.8 }} />
              </div>
              <p
                style={{
                  fontSize: 13,
                  marginTop: 'var(--c--globals--spacings--3, 12px)',
                  color: 'var(--c--contextuals--content--surface--secondary, #666)',
                }}
              >
                {t('settings.safety_fingerprint_hint')}
              </p>
            </div>
          </Modal>

          {/* Add another device via approval (forwards the VRK). */}
          {onOpenDeviceApproval && (
            <div style={{ marginBottom: 'var(--c--globals--spacings--4, 16px)' }}>
              <Button variant="secondary" onClick={onOpenDeviceApproval}>
                {t('settings.add_device')}
              </Button>
            </div>
          )}

          {/* Change the recovery phrase (re-wraps the VRK; documents untouched).
              Stepped so the new phrase is fully backed up before the old one is
              invalidated on the server. */}
          <div style={{ marginBottom: 'var(--c--globals--spacings--4, 16px)' }}>
            <Button
              variant="secondary"
              onClick={() => {
                setChangeError(null);
                setChangePhraseStep('warning');
              }}
            >
              {t('settings.change_phrase')}
            </Button>
          </div>

          {/* Only the confirm-before warning is a modal; on Continue the backup
              step takes over the whole view (handled by the early return above). */}
          <Modal
            isOpen={changePhraseStep === 'warning'}
            onClose={isChangingPhrase ? () => undefined : handleCancelPhrase}
            closeOnClickOutside={false}
            size={ModalSize.LARGE}
            title={t('settings.change_phrase')}
          >
            <div style={{ paddingBottom: 'var(--c--globals--spacings--4, 16px)' }}>
              <Alert type={VariantType.WARNING}>{t('settings.change_phrase_warning')}</Alert>
              {changeError && (
                <div style={{ marginTop: 8 }}>
                  <Alert type={VariantType.ERROR}>{changeError}</Alert>
                </div>
              )}
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
                <Button variant="secondary" onClick={handleCancelPhrase} disabled={isChangingPhrase}>
                  {t('settings.change_phrase_cancel')}
                </Button>
                <Button color="error" onClick={handleGeneratePhrase} disabled={isChangingPhrase}>
                  {isChangingPhrase ? t('settings.changing_phrase') : t('settings.change_phrase_continue')}
                </Button>
              </div>
            </div>
          </Modal>

          {/* Danger zone opens as its own full view (early return above). */}
          <Button variant="tertiary" color="error" onClick={() => setShowDangerZone(true)}>
            {t('settings.show_danger_zone')}
          </Button>
        </>
      )}

      <div style={{ marginTop: 'var(--c--globals--spacings--4, 16px)' }}>
        <Button variant="secondary" onClick={onClose}>
          {t('settings.close')}
        </Button>
      </div>
    </div>
  );
}
