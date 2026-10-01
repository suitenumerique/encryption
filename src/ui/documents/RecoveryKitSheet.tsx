import { type CSSProperties, useEffect, useLayoutEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';

import styles from '@encryption/src/ui/documents/recovery-kit.module.css';
import { runtimeConfig } from '@encryption/src/ui/runtime-config';

// The printable Recovery Kit as one A4 sheet of HTML, printed with the browser's
// own print dialog (which also offers "Save as PDF"). The brand font is the one
// the interface already loads; without it the sheet falls back to Helvetica.
const brandFont = runtimeConfig.brandFont;
const fontStyle = brandFont ? ({ '--recovery-kit-font': `"${brandFont.family}", Helvetica, Arial, sans-serif` } as CSSProperties) : undefined;

export function RecoveryKitSheet({ words, domain }: { words: string[]; domain: string }) {
  const { t } = useTranslation('common');

  return (
    <article className={styles.sheet} style={fontStyle} aria-label={t('onboarding.print_title')}>
      <h1 className={styles.title}>{t('onboarding.print_title')}</h1>
      <p className={styles.warning}>{t('onboarding.print_warning')}</p>
      <p className={styles.label}>{t('onboarding.print_label')}</p>
      <ol className={styles.words}>
        {words.map((word, index) => (
          <li key={index} className={styles.word}>
            <span className={styles.num}>{index + 1}.</span>
            <span>{word}</span>
          </li>
        ))}
      </ol>
      <footer className={styles.footer}>{t('onboarding.print_footer', { domain })}</footer>
    </article>
  );
}

/**
 * Mount the sheet, open the print dialog, and call `onDone` once the dialog
 * closes, whether the user printed or cancelled. The caller unmounts this in
 * `onDone`, so the phrase is in the DOM only while the dialog is open.
 */
export function RecoveryKitPrint({ words, domain, onDone }: { words: string[]; domain: string; onDone: () => void }) {
  const onDoneRef = useRef(onDone);
  useLayoutEffect(() => {
    onDoneRef.current = onDone;
  });

  useEffect(() => {
    const handleAfterPrint = () => onDoneRef.current();
    window.addEventListener('afterprint', handleAfterPrint, { once: true });

    // One frame first so the portal is laid out before the browser snapshots the page.
    const frame = requestAnimationFrame(() => window.print());

    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener('afterprint', handleAfterPrint);
    };
  }, []);

  return createPortal(
    <div className={styles.printRoot}>
      <RecoveryKitSheet words={words} domain={domain} />
    </div>,
    document.body
  );
}
