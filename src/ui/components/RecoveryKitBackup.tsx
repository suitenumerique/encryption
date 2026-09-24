import { Alert, Button, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { Icon } from '@gouvfr-lasuite/ui-kit';
import { pdf } from '@react-pdf/renderer';
import { type ReactNode, useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { type IllustrationName, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { RecoveryKitDocument } from '@encryption/src/ui/documents/RecoveryKitDocument';

interface RecoveryKitBackupProps {
  passphrase: string;
  parentOrigin: string | null;
  onConfirm: () => void;
  confirmLabel: string;
  busyLabel?: string;
  isBusy?: boolean;
  error?: string | null;
  /**
   * 'backup' (default): the OWNER saves their OWN new phrase — copy / file /
   * print, with the confirmation gated on one of them having happened.
   * 'handover': a trusted contact is looking at the GRANTOR's phrase to pass on —
   * persistent-storage options make no sense (it is not theirs to keep), so it
   * shows the phrase itself and a copy action to send it through a secure channel.
   */
  mode?: 'backup' | 'handover';
  title?: ReactNode;
  description?: ReactNode;
  illustration?: IllustrationName;
  banner?: ReactNode;
  back?: { label: string; onClick: () => void; disabled?: boolean };
}

// Split a space-separated recovery phrase into its words. Recovery phrases are
// 24-word BIP-39 mnemonics; the file and printout number them 1..N so they read
// like the restore grid, and the restore input strips that "1." numbering on
// paste, so a saved sheet can be typed or pasted straight back.
function phraseWords(passphrase: string): string[] {
  return passphrase.trim().split(/\s+/).filter(Boolean);
}

function WordGrid({ passphrase }: { passphrase: string }) {
  return (
    <ol className={styles.words}>
      {phraseWords(passphrase).map((word, index) => (
        <li key={index}>
          <span>{word}</span>
        </li>
      ))}
    </ol>
  );
}

/**
 * The "Recovery Kit" backup screen: three ways to keep the phrase (copy, file,
 * print), an on-demand reveal, and a single confirm button that only unlocks
 * once the user did at least one of them. Shared by the initial onboarding
 * backup step, the change-recovery-phrase flow and the post-emergency rotation,
 * so all of them offer the exact same backup UX before anything is committed.
 */
export function RecoveryKitBackup({
  passphrase,
  parentOrigin,
  onConfirm,
  confirmLabel,
  busyLabel,
  isBusy = false,
  error = null,
  mode = 'backup',
  title,
  description,
  illustration,
  banner,
  back,
}: RecoveryKitBackupProps) {
  const { t, i18n } = useTranslation('common');
  const [showPassphrase, setShowPassphrase] = useState(mode === 'handover');
  const [isCopied, setIsCopied] = useState(false);
  // The phrase left the screen through at least one channel (copied, saved,
  // printed, or read on screen): only then may the user claim it is saved.
  const [saved, setSaved] = useState(mode === 'handover');

  const handleCopyPassphrase = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(passphrase);
      setIsCopied(true);
      setSaved(true);
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
    setSaved(true);
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
    setSaved(true);
  }, [passphrase, parentOrigin, i18n.language]);

  const confirmButton = (
    <Button onClick={onConfirm} disabled={isBusy || !saved} fullWidth>
      {isBusy && busyLabel ? busyLabel : confirmLabel}
    </Button>
  );

  // Handover (a contact revealing the grantor's phrase): no persistent-backup
  // framing — just show the phrase and a copy action to send it on. The
  // surrounding RevealView already explains it is the owner's phrase to hand over.
  if (mode === 'handover') {
    return (
      <Screen back={back} title={title} description={description} banner={banner} actions={<>{confirmButton}</>}>
        <WordGrid passphrase={passphrase} />
        <Button
          variant="secondary"
          fullWidth
          color={isCopied ? 'success' : 'brand'}
          onClick={handleCopyPassphrase}
          icon={<Icon aria-hidden name={isCopied ? 'check' : 'content_copy'} />}
        >
          {isCopied ? t('onboarding.btn_copied') : t('emergency.reveal_copy_to_send')}
        </Button>
        {error && <Alert type={VariantType.ERROR}>{error}</Alert>}
      </Screen>
    );
  }

  return (
    <Screen
      back={back}
      illustration={illustration ?? 'shield-check'}
      title={title ?? t('onboarding.title_backup')}
      description={description ?? t('onboarding.backup_description')}
      banner={banner}
      actions={<>{confirmButton}</>}
    >
      <div className={styles.actions}>
        <Button
          variant="secondary"
          color={isCopied ? 'success' : 'brand'}
          onClick={handleCopyPassphrase}
          icon={<Icon aria-hidden name={isCopied ? 'check' : 'content_copy'} />}
        >
          {isCopied ? t('onboarding.btn_copied') : t('onboarding.btn_copy_clipboard')}
        </Button>
        <Button variant="bordered" onClick={handleSaveFile} icon={<Icon aria-hidden name="download" />}>
          {t('onboarding.btn_save_file')}
        </Button>
        <Button variant="bordered" onClick={handlePrint} icon={<Icon aria-hidden name="print" />}>
          {t('onboarding.btn_print')}
        </Button>
      </div>

      {showPassphrase ? (
        <WordGrid passphrase={passphrase} />
      ) : (
        <div style={{ textAlign: 'center' }}>
          <Button
            size="small"
            variant="tertiary"
            color="neutral"
            onClick={() => {
              setShowPassphrase(true);
              setSaved(true);
            }}
            icon={<Icon aria-hidden name="visibility" size={16} />}
          >
            {t('onboarding.btn_reveal')}
          </Button>
        </div>
      )}

      {error && <Alert type={VariantType.ERROR}>{error}</Alert>}
    </Screen>
  );
}
