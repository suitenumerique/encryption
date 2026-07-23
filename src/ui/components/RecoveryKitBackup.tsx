import { Alert, Button, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';

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

  const handlePrint = useCallback(() => {
    function escapeHtml(str: string): string {
      return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    const domain = parentOrigin ?? window.location.origin;
    const footer = t('onboarding.print_footer', { domain });

    const wordsHtml = phraseWords(passphrase)
      .map((w, i) => `<div class="word"><span class="num">${i + 1}.</span> ${escapeHtml(w)}</div>`)
      .join('');

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
      <html lang="${escapeHtml(i18n.language)}">
        <head>
          <title>${escapeHtml(t('onboarding.print_title'))}</title>
          <style>
            body { font-family: system-ui, sans-serif; padding: 40px; max-width: 600px; margin: 0 auto; }
            h1 { font-size: 18px; margin-bottom: 8px; }
            .warning { border-left: 4px solid #b34000; background: #ffe9e6; padding: 12px; margin: 16px 0; font-size: 13px; border-radius: 0 4px 4px 0; }
            .words { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px 24px; font-family: monospace; font-size: 13px; border: 1px solid #ccc; padding: 16px; background: #f9f9f9; margin: 16px 0; }
            .num { color: #888; display: inline-block; width: 22px; text-align: right; margin-right: 6px; }
            .footer { font-size: 11px; color: #999; margin-top: 32px; }
          </style>
        </head>
        <body>
          <h1>${escapeHtml(t('onboarding.print_title'))}</h1>
          <div class="warning">${escapeHtml(t('onboarding.print_warning'))}</div>
          <p>${escapeHtml(t('onboarding.print_label'))}</p>
          <div class="words">${wordsHtml}</div>
          <div class="footer">${escapeHtml(footer)}</div>
        </body>
      </html>
    `);
    doc.close();

    const triggerPrint = () => {
      printFrame.contentWindow?.print();
      setTimeout(() => printFrame.parentNode?.removeChild(printFrame), 1000);
    };

    if (doc.readyState === 'complete') {
      triggerPrint();
    } else {
      printFrame.onload = triggerPrint;
    }
  }, [passphrase, parentOrigin, t, i18n.language]);

  return (
    <>
      <div style={{ marginTop: 12 }}>
        <Alert type={VariantType.WARNING}>{t('onboarding.backup_warning')}</Alert>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 16 }}>
        {/* Option 1: Copy to password manager - Recommended */}
        <div
          style={{
            padding: 'var(--c--globals--spacings--3, 12px)',
            border: '2px solid var(--c--globals--colors--success-500, #18753c)',
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
                background: 'var(--c--globals--colors--success-500, #18753c)',
                color: 'white',
              }}
            >
              {t('onboarding.badge_recommended')}
            </span>
          </div>
          <p style={{ fontSize: 12, margin: '0 0 8px', color: 'var(--c--contextuals--content--semantic--neutral--secondary, #333)' }}>
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

        {/* Option 2: Save as file - Intermediate */}
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
          <p style={{ fontSize: 12, margin: '0 0 8px', color: 'var(--c--contextuals--content--semantic--neutral--secondary, #666)' }}>
            {t('onboarding.backup_option_file_description')}
          </p>
          <Button size="small" variant="secondary" onClick={handleSaveFile}>
            {t('onboarding.btn_save_file')}
          </Button>
        </div>

        {/* Option 3: Print on paper - Discouraged */}
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
          <p style={{ fontSize: 12, margin: '0 0 8px', color: 'var(--c--contextuals--content--semantic--neutral--secondary, #666)' }}>
            {t('onboarding.backup_option_print_description')}
          </p>
          <Button size="small" variant="tertiary" onClick={handlePrint}>
            {t('onboarding.btn_print')}
          </Button>
        </div>

        {/* Reveal passphrase - hidden by default */}
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
                value={passphrase}
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
