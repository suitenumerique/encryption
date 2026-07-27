import { Alert, Button, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { pdf } from '@react-pdf/renderer';
import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { RecoveryKitDocument } from '@encryption/src/ui/documents/RecoveryKitDocument';

interface RecoveryKitBackupProps {
  passphrase: string;
  parentOrigin: string | null;
  onConfirm: () => void;
  confirmLabel: string;
  busyLabel?: string;
  isBusy?: boolean;
  error?: string | null;
  onCancel?: () => void;
  cancelLabel?: string;
  /**
   * 'backup' (default): the OWNER saves their OWN new phrase — full ranked options
   * (password manager / file / print) + the "this is your backup" warning.
   * 'handover': a trusted contact is looking at the GRANTOR's phrase to pass on —
   * the persistent-storage options make no sense (it is not theirs to keep), so it
   * shows only the phrase + a copy action to send it through a secure channel.
   */
  mode?: 'backup' | 'handover';
}

// Split a space-separated recovery phrase into its words. Recovery phrases are
// 24-word BIP-39 mnemonics; the file and printout number them 1..N so they read
// like the restore grid, and the restore input strips that "1." numbering on
// paste, so a saved sheet can be typed or pasted straight back.
function phraseWords(passphrase: string): string[] {
  return passphrase.trim().split(/\s+/).filter(Boolean);
}

/**
 * The "Recovery Kit" backup screen: a WARNING, three save options (password
 * manager, file, print) ranked by safety, and a reveal-to-copy fallback, ending
 * in a single confirm button. Shared by the initial onboarding backup step and
 * the change-recovery-phrase flow so both offer the exact same, complete backup
 * UX before anything is committed to the server.
 */
export function RecoveryKitBackup({
  passphrase,
  parentOrigin,
  onConfirm,
  confirmLabel,
  busyLabel,
  isBusy = false,
  error = null,
  onCancel,
  cancelLabel,
  mode = 'backup',
}: RecoveryKitBackupProps) {
  const { t, i18n } = useTranslation('common');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [isCopied, setIsCopied] = useState(false);

  const handleCopyPassphrase = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(passphrase);
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 3000);
    } catch {
      // Clipboard may not be available in iframes
    }
  }, [passphrase]);

  const handleSaveFile = useCallback(() => {
    const numbered = phraseWords(passphrase)
      .map((w, i) => `${i + 1}. ${w}`)
      .join('\n');
    const content = `${t('onboarding.print_title')}\n\n${t('onboarding.print_label')}\n\n${numbered}\n\n${t('onboarding.print_warning')}\n`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'encryption-recovery-phrase.txt';
    a.click();
    URL.revokeObjectURL(url);
  }, [passphrase, t]);

  const handlePrint = useCallback(async () => {
    const domain = parentOrigin ?? window.location.origin;
    const blob = await pdf(<RecoveryKitDocument words={phraseWords(passphrase)} lang={i18n.language} domain={domain} />).toBlob();
    const url = URL.createObjectURL(blob);

    // Print via a hidden iframe pointed at the PDF blob: the browser loads its PDF
    // viewer in the frame and prints that. A hidden iframe (rather than a new tab)
    // keeps this working inside the sandboxed interface iframe, with no popup
    // permission needed.
    const printFrame = document.createElement('iframe');
    printFrame.style.position = 'fixed';
    printFrame.style.left = '-9999px';
    printFrame.style.width = '0';
    printFrame.style.height = '0';
    printFrame.src = url;
    printFrame.onload = () => {
      printFrame.contentWindow?.focus();
      printFrame.contentWindow?.print();
      setTimeout(() => {
        printFrame.parentNode?.removeChild(printFrame);
        URL.revokeObjectURL(url);
      }, 1000);
    };
    document.body.appendChild(printFrame);
  }, [passphrase, parentOrigin, i18n.language]);

  // Handover (a contact revealing the grantor's phrase): no persistent-backup
  // framing — just show the phrase and a copy action to send it on. The
  // surrounding RevealView already explains it is the owner's phrase to hand over.
  if (mode === 'handover') {
    return (
      <>
        <div
          style={{
            marginTop: 12,
            padding: 'var(--c--globals--spacings--sm)',
            border: '1px solid var(--c--contextuals--border--surface--primary)',
            borderRadius: 4,
            background: 'var(--c--contextuals--background--surface--secondary)',
          }}
        >
          <p style={{ fontSize: 13, fontWeight: 700, margin: '0 0 8px' }}>{t('emergency.reveal_phrase_label')}</p>
          <textarea
            readOnly
            value={passphrase}
            rows={4}
            style={{
              width: '100%',
              fontFamily: 'monospace',
              fontSize: 12,
              boxSizing: 'border-box',
              lineHeight: 1.4,
              userSelect: 'all',
              borderRadius: 4,
              border: '1px solid var(--c--contextuals--border--surface--primary)',
              background: 'var(--c--contextuals--background--surface--primary)',
              color: 'var(--c--contextuals--content--semantic--neutral--primary)',
            }}
          />
          <div style={{ marginTop: 8 }}>
            <Button
              size="small"
              onClick={handleCopyPassphrase}
              icon={
                isCopied ? (
                  <span className="material-icons" style={{ fontSize: 16 }}>
                    check
                  </span>
                ) : undefined
              }
            >
              {isCopied ? t('onboarding.btn_copied') : t('emergency.reveal_copy_to_send')}
            </Button>
          </div>
        </div>

        {error && (
          <div style={{ marginTop: 12 }}>
            <Alert type={VariantType.ERROR}>{error}</Alert>
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          {onCancel && (
            <Button variant="secondary" onClick={onCancel} disabled={isBusy}>
              {cancelLabel}
            </Button>
          )}
          <Button onClick={onConfirm} disabled={isBusy}>
            {isBusy && busyLabel ? busyLabel : confirmLabel}
          </Button>
        </div>
      </>
    );
  }

  return (
    <>
      <div style={{ marginTop: 12 }}>
        <Alert type={VariantType.WARNING}>{t('onboarding.backup_warning')}</Alert>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 16 }}>
        {/* Option 1: Copy to password manager - Recommended */}
        <div
          style={{
            padding: 'var(--c--globals--spacings--sm)',
            border: '2px solid var(--c--globals--colors--success-500)',
            borderRadius: 4,
            background: 'var(--c--contextuals--background--semantic--success--secondary)',
            color: 'var(--c--contextuals--content--semantic--success--secondary)',
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
                background: 'var(--c--contextuals--background--semantic--success--primary)',
                color: 'var(--c--contextuals--content--semantic--success--on-success)',
              }}
            >
              {t('onboarding.badge_recommended')}
            </span>
          </div>
          <p style={{ fontSize: 12, margin: '0 0 8px', color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>
            {t('onboarding.backup_option_copy_description')}
          </p>
          <Button
            size="small"
            variant="secondary"
            onClick={handleCopyPassphrase}
            icon={
              isCopied ? (
                <span className="material-icons" style={{ fontSize: 16 }}>
                  check
                </span>
              ) : undefined
            }
          >
            {isCopied ? t('onboarding.btn_copied') : t('onboarding.btn_copy_clipboard')}
          </Button>
        </div>

        {/* Option 2: Save as file */}
        <div
          style={{
            padding: 'var(--c--globals--spacings--sm)',
            border: '1px solid var(--c--contextuals--border--surface--primary)',
            borderRadius: 4,
          }}
        >
          <span style={{ fontWeight: 700, fontSize: 14, display: 'block', marginBottom: 4 }}>{t('onboarding.backup_option_file')}</span>
          <p style={{ fontSize: 12, margin: '0 0 8px', color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>
            {t('onboarding.backup_option_file_description')}
          </p>
          <Button size="small" variant="secondary" onClick={handleSaveFile}>
            {t('onboarding.btn_save_file')}
          </Button>
        </div>

        {/* Option 3: Print on paper */}
        <div
          style={{
            padding: 'var(--c--globals--spacings--sm)',
            border: '1px solid var(--c--contextuals--border--surface--primary)',
            borderRadius: 4,
          }}
        >
          <span style={{ fontWeight: 700, fontSize: 14, display: 'block', marginBottom: 4 }}>{t('onboarding.backup_option_print')}</span>
          <p style={{ fontSize: 12, margin: '0 0 8px', color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>
            {t('onboarding.backup_option_print_description')}
          </p>
          <Button size="small" variant="secondary" onClick={handlePrint}>
            {t('onboarding.btn_print')}
          </Button>
        </div>

        {/* Reveal passphrase - hidden by default */}
        <div
          style={{
            padding: 'var(--c--globals--spacings--sm)',
            border: '1px solid var(--c--contextuals--border--surface--primary)',
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
                value={passphrase}
                rows={4}
                style={{
                  width: '100%',
                  fontFamily: 'monospace',
                  fontSize: 10,
                  boxSizing: 'border-box',
                  lineHeight: 1.4,
                  userSelect: 'all',
                  borderRadius: 4,
                  border: '1px solid var(--c--contextuals--border--surface--primary)',
                  background: 'var(--c--contextuals--background--surface--primary)',
                  color: 'var(--c--contextuals--content--semantic--neutral--primary)',
                }}
              />
            </>
          )}
        </div>
      </div>

      {error && (
        <div style={{ marginTop: 12 }}>
          <Alert type={VariantType.ERROR}>{error}</Alert>
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
        {onCancel && (
          <Button variant="secondary" onClick={onCancel} disabled={isBusy}>
            {cancelLabel}
          </Button>
        )}
        <Button onClick={onConfirm} disabled={isBusy}>
          {isBusy && busyLabel ? busyLabel : confirmLabel}
        </Button>
      </div>
    </>
  );
}
