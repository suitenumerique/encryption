import { Alert, Button, Loader, TextArea, VariantType } from '@gouvfr-lasuite/cunningham-react';
import type { TFunction } from 'i18next';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { formatFingerprint } from '@encryption/src/crypto/fingerprint';
import type { UserInfo } from '@encryption/src/ui/App';
import { completeKeyPossession, disablePublicKey, initKeyPossession } from '@encryption/src/ui/api/server-client';
import {
  SessionExpiredError,
  withFreshToken,
} from '@encryption/src/ui/auth/session-expired';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

type OnboardingStep = 'explanation' | 'existing-key-choice' | 'last-resort' | 'generating' | 'restore' | 'backup';

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
          <p style={{ fontSize: 13, margin: '0 0 8px' }}>
            {t('onboarding.confirm_fingerprint_to_delete')}
          </p>
          <div
            style={{
              fontFamily: 'monospace',
              fontSize: 14,
              letterSpacing: '0.05em',
              padding: 'var(--c--globals--spacings--2, 8px)',
              background: 'var(--c--contextuals--background--surface--secondary, #f5f5fe)',
              borderRadius: 4,
              marginBottom: 8,
            }}
          >
            {formatFingerprint(existingKeyFingerprint!)}
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
              fontSize: 13,
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
  onOpenDeviceTransfer?: () => void;
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

export function ModalEncryptionOnboarding({
  getToken,
  userId,
  hasExistingBackendKey = false,
  parentOrigin = null,
  existingKeyFingerprint = null,
  userInfo = null,
  onSuccess,
  onClose,
  onOpenDeviceTransfer,
  onReconnect,
  isAuthenticating = false,
  currentAccessToken = null,
}: ModalEncryptionOnboardingProps) {
  const { t } = useTranslation('common');
  const { generateKeys, getPublicKey, exportBackup, importBackup, request, respondToKeyChallenge } = useEncryptionContext();

  const [step, setStep] = useState<OnboardingStep>(hasExistingBackendKey ? 'existing-key-choice' : 'explanation');
  const [isPending, setIsPending] = useState(false);
  const [backupPassphrase, setBackupPassphrase] = useState<string | null>(null);
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [restoreInput, setRestoreInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [sessionExpired, setSessionExpired] = useState(false);
  // Snapshot of the access token the moment we latched onto the
  // session-expired state. A subsequent change in `currentAccessToken`
  // relative to this snapshot means the Reconnect flow produced a fresh
  // token — at that point we auto-clear the banner.
  const [expiredAtToken, setExpiredAtToken] = useState<string | null>(null);
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
    if (hasExistingBackendKey && step === 'explanation' && !hasJustReset) {
      setStep('existing-key-choice');
    }
  }, [hasExistingBackendKey, step, hasJustReset]);

  useEffect(() => {
    if (
      sessionExpired &&
      !isAuthenticating &&
      currentAccessToken &&
      currentAccessToken !== expiredAtToken
    ) {
      setSessionExpired(false);
      setExpiredAtToken(null);
    }
  }, [sessionExpired, isAuthenticating, currentAccessToken, expiredAtToken]);

  const markSessionExpired = useCallback(() => {
    setExpiredAtToken(currentAccessToken);
    setSessionExpired(true);
  }, [currentAccessToken]);

  // Two-phase proof-of-possession registration, used by both the fresh
  // generate flow and the backup-restore flow. The vault decapsulates
  // the server's challenge ciphertext using the just-stored secret key,
  // so we know the user holds the matching private key before the
  // server commits the new public key.
  const registerKeyWithPoP = useCallback(
    async (publicKeyToRegister: string): Promise<void> => {
      if (!userId) return;
      await withFreshToken(getToken, async (token) => {
        const { challengeId, ciphertext } = await initKeyPossession(token, userId, publicKeyToRegister);
        const { response } = await respondToKeyChallenge(challengeId, ciphertext);
        await completeKeyPossession(token, challengeId, response);
      });
    },
    [getToken, userId, respondToKeyChallenge],
  );

  const handleGenerateKeys = useCallback(async () => {
    setIsPending(true);
    setError(null);
    setSessionExpired(false);

    try {
      const { publicKey } = await generateKeys();

      // Register the public key on the encryption server through the
      // proof-of-possession flow (the central authority requires the user
      // to demonstrate they hold the matching private key). Without
      // server registration, other products and users cannot discover
      // this user's public key. If any step fails, destroy the local keys
      // to prevent an inconsistent state.
      if (userId) {
        try {
          await registerKeyWithPoP(publicKey);
        } catch (regError) {
          // Clean up local keys regardless of the specific failure mode —
          // a key that doesn't exist on the server is useless and would
          // leave the user in an inconsistent state.
          try {
            await request('vault:destroy-keys');
          } catch {
            // Best effort cleanup
          }
          if (regError instanceof SessionExpiredError) {
            throw regError;
          }
          throw new Error(t('errors.vault.registration_failed'));
        }
      }

      const backup = await exportBackup();
      setBackupPassphrase(backup.passphrase);
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
  }, [generateKeys, exportBackup, request, getToken, userId, t, markSessionExpired]);

  const handleResetFromZero = useCallback(async () => {
    setIsPending(true);
    setError(null);
    setSessionExpired(false);

    try {
      // Disable the existing public key on the server, then move the
      // user straight into the fresh-onboarding flow inside the same
      // modal. Previously we closed on success, which left the user
      // stranded with no confirmation and required them to re-open the
      // encryption modal to create new keys. `withFreshToken` turns a
      // failed OIDC refresh into a recoverable `SessionExpiredError`
      // surfaced via the Reconnect UI.
      await withFreshToken(getToken, (token) => disablePublicKey(token));
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
  }, [getToken, markSessionExpired]);

  const handleRestoreKeys = useCallback(async () => {
    if (!restoreInput.trim()) return;

    setIsPending(true);
    setError(null);
    setSessionExpired(false);

    try {
      const { publicKey } = await importBackup(restoreInput.trim());

      if (userId) {
        try {
          await registerKeyWithPoP(publicKey);
        } catch (regError) {
          // Clean up local keys — they're useless without server
          // registration, whether the cause is an expired session or a
          // 5xx from the registration endpoint.
          try {
            await request('vault:destroy-keys');
          } catch {
            // Best effort
          }
          if (regError instanceof SessionExpiredError) {
            throw regError;
          }
          throw new Error(t('errors.vault.registration_failed'));
        }
      }

      onSuccess?.(publicKey);
      onClose();
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        markSessionExpired();
      } else {
        const msg = (err as Error).message;
        // Preserve our own specific error; fall back to "invalid backup"
        // only when the failure is the importBackup step.
        if (msg === t('errors.vault.registration_failed')) {
          setError(msg);
        } else {
          setError(t('errors.vault.invalid_backup'));
        }
      }
    } finally {
      setIsPending(false);
    }
  }, [restoreInput, importBackup, request, getToken, userId, onSuccess, onClose, t, markSessionExpired]);

  const [isCopied, setIsCopied] = useState(false);

  const handleCopyPassphrase = useCallback(async () => {
    if (!backupPassphrase) return;

    try {
      await navigator.clipboard.writeText(backupPassphrase);
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 3000);
    } catch {
      // Clipboard may not be available in iframes
    }
  }, [backupPassphrase]);

  const handleSaveFile = useCallback(() => {
    if (!backupPassphrase) return;

    const blob = new Blob([backupPassphrase], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'encryption-recovery-phrase.txt';
    a.click();
    URL.revokeObjectURL(url);
  }, [backupPassphrase]);

  const handlePrint = useCallback(() => {
    if (!backupPassphrase) return;

    function escapeHtml(str: string): string {
      return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    const domain = parentOrigin ?? window.location.origin;
    const footer = t('onboarding.print_footer', { domain });

    // Use a hidden iframe to trigger print without opening a new tab.
    // This works inside sandboxed iframes (allow-popups not needed).
    const printFrame = document.createElement('iframe');
    printFrame.style.position = 'fixed';
    printFrame.style.left = '-9999px';
    printFrame.style.width = '0';
    printFrame.style.height = '0';
    document.body.appendChild(printFrame);

    const doc = printFrame.contentDocument ?? printFrame.contentWindow?.document;

    if (!doc) {
      document.body.removeChild(printFrame);

      return;
    }

    doc.open();
    doc.write(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>${escapeHtml(t('onboarding.print_title'))}</title>
          <style>
            body { font-family: system-ui, sans-serif; padding: 40px; max-width: 600px; margin: 0 auto; }
            h1 { font-size: 18px; margin-bottom: 8px; }
            .warning { border-left: 4px solid #b34000; background: #ffe9e6; padding: 12px; margin: 16px 0; font-size: 13px; border-radius: 0 4px 4px 0; }
            .passphrase { font-family: monospace; font-size: 11px; line-height: 1.5; word-break: break-all; border: 1px solid #ccc; padding: 12px; background: #f9f9f9; margin: 16px 0; }
            .footer { font-size: 11px; color: #999; margin-top: 32px; }
          </style>
        </head>
        <body>
          <h1>${escapeHtml(t('onboarding.print_title'))}</h1>
          <div class="warning">${escapeHtml(t('onboarding.print_warning'))}</div>
          <p>${escapeHtml(t('onboarding.print_label'))}</p>
          <div class="passphrase">${escapeHtml(backupPassphrase)}</div>
          <div class="footer">${escapeHtml(footer)}</div>
        </body>
      </html>
    `);
    doc.close();

    const triggerPrint = () => {
      printFrame.contentWindow?.print();
      setTimeout(() => printFrame.parentNode?.removeChild(printFrame), 1000);
    };

    // If the document is already loaded (synchronous write), print immediately.
    // Otherwise wait for the load event.
    if (doc.readyState === 'complete') {
      triggerPrint();
    } else {
      printFrame.onload = triggerPrint;
    }
  }, [backupPassphrase, parentOrigin, t]);

  const handleBackupDone = useCallback(async () => {
    try {
      const { publicKey } = await getPublicKey();
      onSuccess?.(publicKey);
    } catch {
      // Key was already generated, just close
    }

    onClose();
  }, [getPublicKey, onSuccess, onClose]);

  return (
    <div style={{ padding: 'var(--c--globals--spacings--4, 16px)' }}>
      {sessionExpired && onReconnect && (
        <SessionExpiredAlert
          onReconnect={onReconnect}
          isAuthenticating={isAuthenticating}
        />
      )}
      {error && <Alert type={VariantType.ERROR}>{error}</Alert>}

      {step === 'explanation' && (
        <>
          {hasJustReset && (
            <Alert type={VariantType.SUCCESS}>
              {t(
                'onboarding.reset_success',
                'Your previous encryption key has been deleted. You can now set up a new one.',
              )}
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
                  fontFamily: 'monospace',
                  fontSize: 16,
                  letterSpacing: '0.05em',
                  padding: 'var(--c--globals--spacings--2, 8px)',
                  background: 'var(--c--contextuals--background--surface--primary, #fff)',
                  borderRadius: 4,
                }}
              >
                {formatFingerprint(existingKeyFingerprint)}
              </div>
            </div>
          )}

          <p style={{ fontSize: 13, color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>{t('onboarding.existing_recovery_hint')}</p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 16 }}>
            <Button variant="secondary" fullWidth onClick={() => setStep('restore')}>
              {t('onboarding.btn_restore_from_backup')}
            </Button>
            {onOpenDeviceTransfer && (
              <Button variant="secondary" fullWidth onClick={onOpenDeviceTransfer}>
                {t('onboarding.btn_device_transfer')}
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
          <TextArea
            label={t('onboarding.restore_placeholder')}
            value={restoreInput}
            onChange={(e) => setRestoreInput(e.target.value)}
            rows={5}
            fullWidth
            style={{ fontFamily: 'monospace', fontSize: 12, marginTop: 8 }}
          />
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
            <Button
              variant="secondary"
              onClick={() => {
                setError(null);
                setRestoreInput('');
                setStep(hasExistingBackendKey ? 'existing-key-choice' : 'explanation');
              }}
            >
              {t('onboarding.btn_back')}
            </Button>
            <Button onClick={handleRestoreKeys} disabled={isPending || !restoreInput.trim()}>
              {isPending ? t('onboarding.btn_restoring') : t('onboarding.btn_restore')}
            </Button>
          </div>
        </>
      )}

      {step === 'backup' && (
        <>
          <h2>{t('onboarding.title_backup')}</h2>
          <Alert type={VariantType.SUCCESS}>{t('onboarding.backup_success')}</Alert>

          <div style={{ marginTop: 12 }}>
            <Alert type={VariantType.WARNING}>{t('onboarding.backup_warning')}</Alert>
          </div>

          {backupPassphrase && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 16 }}>
              {/* Option 1: Copy to password manager — Recommended */}
              <div
                style={{
                  padding: 'var(--c--globals--spacings--3, 12px)',
                  border: '2px solid var(--c--globals--colors--success-500, #18753c)',
                  borderRadius: 4,
                  background: 'var(--c--contextuals--background--semantic--contextual--success, #b8fec9)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <span style={{ fontWeight: 700, fontSize: 14 }}>{t('onboarding.backup_option_copy')}</span>
                  <span
                    style={{
                      fontSize: 11,
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: 10,
                      background: 'var(--c--globals--colors--success-500, #18753c)',
                      color: 'white',
                    }}
                  >
                    {t('onboarding.badge_recommended')}
                  </span>
                </div>
                <p style={{ fontSize: 12, margin: '0 0 8px', color: 'var(--c--contextuals--content--surface--secondary, #333)' }}>
                  {t('onboarding.backup_option_copy_description')}
                </p>
                <Button size="small" variant="secondary" onClick={handleCopyPassphrase} icon={isCopied ? <span className="material-icons" style={{ fontSize: 16 }}>check</span> : undefined}>
                  {isCopied ? t('onboarding.btn_copied') : t('onboarding.btn_copy_clipboard')}
                </Button>
              </div>

              {/* Option 2: Save as file — Intermediate */}
              <div
                style={{
                  padding: 'var(--c--globals--spacings--3, 12px)',
                  border: '1px solid var(--c--contextuals--border--surface--primary, #ddd)',
                  borderRadius: 4,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontWeight: 700, fontSize: 14 }}>{t('onboarding.backup_option_file')}</span>
                  <span
                    style={{
                      fontSize: 11,
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: 10,
                      background: 'var(--c--globals--colors--info-500, #0063cb)',
                      color: 'white',
                    }}
                  >
                    {t('onboarding.badge_intermediate')}
                  </span>
                </div>
                <p style={{ fontSize: 12, margin: '0 0 8px', color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
                  {t('onboarding.backup_option_file_description')}
                </p>
                <Button size="small" variant="secondary" onClick={handleSaveFile}>
                  {t('onboarding.btn_save_file')}
                </Button>
              </div>

              {/* Option 3: Print on paper — Discouraged */}
              <div
                style={{
                  padding: 'var(--c--globals--spacings--3, 12px)',
                  border: '1px solid var(--c--contextuals--border--surface--primary, #ddd)',
                  borderRadius: 4,
                  opacity: 0.8,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontWeight: 700, fontSize: 14 }}>{t('onboarding.backup_option_print')}</span>
                  <span
                    style={{
                      fontSize: 11,
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: 10,
                      background: 'var(--c--globals--colors--warning-500, #b34000)',
                      color: 'white',
                    }}
                  >
                    {t('onboarding.badge_discouraged')}
                  </span>
                </div>
                <p style={{ fontSize: 12, margin: '0 0 8px', color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
                  {t('onboarding.backup_option_print_description')}
                </p>
                <Button size="small" variant="tertiary" onClick={handlePrint}>
                  {t('onboarding.btn_print')}
                </Button>
              </div>

              {/* Reveal passphrase — hidden by default */}
              <div
                style={{
                  padding: 'var(--c--globals--spacings--3, 12px)',
                  border: '1px solid var(--c--contextuals--border--surface--primary, #ddd)',
                  borderRadius: 4,
                }}
              >
                {!showPassphrase ? (
                  <>
                    <p style={{ fontSize: 13, margin: '0 0 8px' }}>{t('onboarding.reveal_description')}</p>
                    <Button size="small" variant="tertiary" onClick={() => setShowPassphrase(true)}>
                      {t('onboarding.btn_reveal')}
                    </Button>
                  </>
                ) : (
                  <>
                    <p style={{ fontSize: 13, fontWeight: 700, margin: '0 0 8px' }}>{t('onboarding.passphrase_label')}</p>
                    <textarea
                      readOnly
                      value={backupPassphrase}
                      rows={4}
                      style={{
                        width: '100%',
                        fontFamily: 'monospace',
                        fontSize: 10,
                        boxSizing: 'border-box',
                        lineHeight: 1.4,
                        userSelect: 'all',
                      }}
                    />
                  </>
                )}
              </div>
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
            <Button onClick={handleBackupDone}>{t('onboarding.btn_backup_done')}</Button>
          </div>
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
