import { Button, Tooltip, UserAvatar } from '@gouvfr-lasuite/ui-components';
import { Ban, Checkmark2, CircleCheck, Clock, Copy, ShieldAlert, Unlock, Warning } from '@gouvfr-lasuite/ui-components/icons';
import { type ReactNode, useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
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

// Which of an identity's two lines the ellipsis cuts, measured on the text column
// (the tooltip takes the ref of the line it wraps, so the lines are found by
// their data attribute), again whenever the column is resized, and once the web
// fonts have loaded (they change the text's width, not the column's).
function useCutLines(name: string, line: string | null) {
  const columnRef = useRef<HTMLDivElement>(null);
  const [cut, setCut] = useState({ name: false, line: false });

  useLayoutEffect(() => {
    const column = columnRef.current;
    if (!column) return;

    // The text's own width against its box, both unrounded: scrollWidth and
    // clientWidth round to whole pixels, so a text overflowing by less than one
    // would show its ellipsis while measuring as fitting.
    const isCut = (selector: string) => {
      const element = column.querySelector<HTMLElement>(selector);
      if (element === null) return false;

      const text = document.createRange();
      text.selectNodeContents(element);

      return text.getBoundingClientRect().width > element.getBoundingClientRect().width;
    };
    const measure = () => setCut({ name: isCut('[data-line="name"]'), line: isCut('[data-line="secondary"]') });
    const observer = new ResizeObserver(measure);
    let active = true;

    measure();
    observer.observe(column);
    void document.fonts.ready.then(() => {
      if (active) measure();
    });

    return () => {
      active = false;
      observer.disconnect();
    };
  }, [name, line]);

  return { columnRef, cut };
}

// How long the pointer rests on a line before its tooltip shows, as a `title`.
const TOOLTIP_REST_MS = 500;

// Mounted when the tooltip opens: marks itself rested once the pointer stayed,
// which reveals the tooltip (see .identity__tooltip).
function RestedTooltipText({ text }: { text: string }) {
  const [rested, setRested] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setRested(true), TOOLTIP_REST_MS);

    return () => clearTimeout(timer);
  }, []);

  return <span className={rested ? styles.identityTooltipRested : undefined}>{text}</span>;
}

/** One line of an identity, with its full text in a tooltip when there is more than it shows. */
function IdentityLine({ className, kind, text, tooltip }: { className: string; kind: 'name' | 'secondary'; text: string; tooltip: string | null }) {
  const element = (
    <p className={className} data-line={kind}>
      {text}
    </p>
  );

  return tooltip ? (
    <Tooltip content={<RestedTooltipText text={tooltip} />} placement="top" className={styles.identityTooltip}>
      {element}
    </Tooltip>
  ) : (
    element
  );
}

/**
 * A person: avatar, name, and their email under it when nothing else takes that
 * line; when it does (a contact's wait period), the email shows on hovering the
 * name (and is read after it by a screen reader, which no tooltip reaches on a
 * line that takes no focus). A person whose name is not known yet is named by
 * their email, once. A line cut by the ellipsis shows in full on hovering it.
 */
export function Identity({ name, email, secondary }: { name: string; email?: string; secondary?: string | null }) {
  const distinctEmail = email && email !== name ? email : null;
  const line = secondary ?? distinctEmail;
  const hiddenEmail = secondary && distinctEmail ? distinctEmail : null;
  const { columnRef, cut } = useCutLines(name, line);
  const nameTooltip = cut.name ? (hiddenEmail ? `${name} (${hiddenEmail})` : name) : hiddenEmail;

  return (
    <div className={styles.identity}>
      <span aria-hidden="true">
        <UserAvatar fullName={name} size="small" />
      </span>
      <div className={styles.identityText} ref={columnRef}>
        <IdentityLine className={styles.identityName} kind="name" text={name} tooltip={nameTooltip} />
        {hiddenEmail && <span className={styles.visuallyHidden}>{hiddenEmail}</span>}
        {line && <IdentityLine className={styles.identitySecondary} kind="secondary" text={line} tooltip={cut.line ? line : null} />}
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
  email?: string;
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
export function IdentityCard({ name, email, secondary, fingerprint, tone = 'default', aside, children }: IdentityCardProps) {
  return (
    <div className={tone === 'default' ? styles.card : `${styles.card} ${CARD_TONE_CLASS[tone]}`}>
      <div className={styles.cardHeader}>
        <Identity name={name} email={email} secondary={secondary} />
        {aside && <div className={styles.cardAside}>{aside}</div>}
      </div>
      {fingerprint && <FingerprintBoxes fingerprint={fingerprint} tone={tone} />}
      {children}
    </div>
  );
}
