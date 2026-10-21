import { Button, UserAvatar } from '@gouvfr-lasuite/ui-components';
import { Ban, Checkmark2, CircleCheck, Clock, Copy, ShieldAlert, Unlock, Warning } from '@gouvfr-lasuite/ui-components/icons';
import { type ReactNode, useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { normalizeDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';
import styles from '@encryption/src/ui/components/layout/layout.module.css';

type Tone = 'default' | 'warning' | 'error' | 'success';
type ChipTone = 'warning' | 'error' | 'success' | 'info' | 'neutral';
export type ChipIcon = 'trusted' | 'warning' | 'refused' | 'alert' | 'pending' | 'unlocked';

const CHIP_TONE_CLASS: Record<ChipTone, string> = {
  warning: styles.chipWarning,
  error: styles.chipError,
  success: styles.chipSuccess,
  info: styles.chipInfo,
  neutral: styles.chipNeutral,
};
const CHIP_ICONS: Record<ChipIcon, ReactNode> = {
  trusted: <CircleCheck aria-hidden size={16} />,
  warning: <Warning aria-hidden size={16} />,
  refused: <Ban aria-hidden size={16} />,
  alert: <ShieldAlert aria-hidden size={16} />,
  pending: <Clock aria-hidden size={16} />,
  unlocked: <Unlock aria-hidden size={16} />,
};
const FINGERPRINT_TONE_CLASS: Record<Exclude<Tone, 'default'>, string> = {
  warning: styles.fingerprintWarning,
  error: styles.fingerprintError,
  success: styles.fingerprintSuccess,
};
const CARD_TONE_CLASS: Record<Exclude<Tone, 'default'>, string> = {
  warning: styles.cardWarning,
  error: styles.cardError,
  success: styles.cardSuccess,
};

/** Name over a secondary line (an email, an organization), with the design system's avatar. */
export function Identity({ name, secondary }: { name: string; secondary?: string | null }) {
  return (
    <div className={styles.identity}>
      <span aria-hidden="true">
        <UserAvatar fullName={name} size="small" />
      </span>
      <div className={styles.identityText}>
        <p className={styles.identityName} title={name}>
          {name}
        </p>
        {secondary && (
          <p className={styles.identitySecondary} title={secondary}>
            {secondary}
          </p>
        )}
      </div>
    </div>
  );
}

export function Chip({ tone, icon, children }: { tone: ChipTone; icon?: ChipIcon; children: ReactNode }) {
  return (
    <span className={`${styles.chip} ${CHIP_TONE_CLASS[tone]}`}>
      {icon && CHIP_ICONS[icon]}
      {children}
    </span>
  );
}

/** The 40-digit safety fingerprint as 8 boxed groups of 5 digits. */
export function FingerprintBoxes({ fingerprint, tone = 'default' }: { fingerprint: string; tone?: Tone }) {
  const groups = normalizeDecimalFingerprint(fingerprint).match(/\d{5}/g) ?? [];

  return (
    <div className={styles.fingerprintWrap}>
      <div
        className={tone === 'default' ? styles.fingerprint : `${styles.fingerprint} ${FINGERPRINT_TONE_CLASS[tone]}`}
        aria-label={groups.join(' ')}
      >
        {groups.map((group, index) => (
          <span key={index} className={styles.fingerprintGroup}>
            {group}
          </span>
        ))}
      </div>
    </div>
  );
}

/** Copy control for a fingerprint; swaps to a check for a moment once copied. */
export function CopyFingerprintButton({ fingerprint, label }: { fingerprint: string; label?: string }) {
  const { t } = useTranslation('common');
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(normalizeDecimalFingerprint(fingerprint));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard may be unavailable inside a sandboxed iframe.
    }
  }, [fingerprint]);

  const accessibleLabel = copied ? t('identity.copied') : t('identity.copy_fingerprint');

  return (
    <Button
      size="nano"
      variant="tertiary"
      color={copied ? 'success' : 'neutral'}
      aria-label={label ? undefined : accessibleLabel}
      title={accessibleLabel}
      icon={copied ? <Checkmark2 aria-hidden size={16} /> : <Copy aria-hidden size={16} />}
      onClick={copy}
    >
      {label && (copied ? t('identity.copied') : label)}
    </Button>
  );
}

interface IdentityCardProps {
  name: string;
  secondary?: string | null;
  fingerprint?: string | null;
  tone?: Tone;
  /** Top-right slot: status chips, the copy control. */
  aside?: ReactNode;
  children?: ReactNode;
}

/**
 * An identity (avatar, name, email) with its safety fingerprint, the block
 * users compare out of band. `tone` colours the border and the digit boxes
 * (warning for a changed key, error for a refused one).
 */
export function IdentityCard({ name, secondary, fingerprint, tone = 'default', aside, children }: IdentityCardProps) {
  return (
    <div className={tone === 'default' ? styles.card : `${styles.card} ${CARD_TONE_CLASS[tone]}`}>
      <div className={styles.cardHeader}>
        <Identity name={name} secondary={secondary} />
        {aside && <div className={styles.cardAside}>{aside}</div>}
      </div>
      {fingerprint && <FingerprintBoxes fingerprint={fingerprint} tone={tone} />}
      {children}
    </div>
  );
}
