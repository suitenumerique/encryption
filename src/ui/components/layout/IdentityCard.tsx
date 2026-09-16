import { Button } from '@gouvfr-lasuite/cunningham-react';
import { type ReactNode, useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { normalizeDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';
import { Icon } from '@encryption/src/ui/components/layout/Screen';
import '@encryption/src/ui/components/layout/layout.css';

type Tone = 'default' | 'warning' | 'error' | 'success';

export function initialsOf(label: string): string {
  return (
    label
      .trim()
      .split(/[\s.@_-]+/)
      .filter(Boolean)
      .map((part) => part[0])
      .join('')
      .slice(0, 2)
      .toUpperCase() || '?'
  );
}

export function Avatar({ label, size = 'medium' }: { label: string; size?: 'medium' | 'large' }) {
  return (
    <span className={size === 'large' ? 'enc-avatar enc-avatar--large' : 'enc-avatar'} aria-hidden="true">
      {initialsOf(label)}
    </span>
  );
}

/** Name over email (or email alone), with an avatar. */
export function Identity({ name, secondary, avatarSize }: { name: string; secondary?: string | null; avatarSize?: 'medium' | 'large' }) {
  return (
    <div className="enc-identity">
      <Avatar label={name} size={avatarSize} />
      <div className="enc-identity__text">
        <p className="enc-identity__name" title={name}>
          {name}
        </p>
        {secondary && (
          <p className="enc-identity__secondary" title={secondary}>
            {secondary}
          </p>
        )}
      </div>
    </div>
  );
}

export function Chip({ tone, icon, children }: { tone: 'warning' | 'error' | 'success' | 'info' | 'neutral'; icon?: string; children: ReactNode }) {
  return (
    <span className={`enc-chip enc-chip--${tone}`}>
      {icon && <Icon name={icon} size={16} />}
      {children}
    </span>
  );
}

/** The 40-digit safety fingerprint as 8 boxed groups of 5 digits. */
export function FingerprintBoxes({ fingerprint, tone = 'default' }: { fingerprint: string; tone?: Tone }) {
  const groups = normalizeDecimalFingerprint(fingerprint).match(/\d{5}/g) ?? [];

  return (
    <div className="enc-fingerprint-wrap">
      <div className={tone === 'default' ? 'enc-fingerprint' : `enc-fingerprint enc-fingerprint--${tone}`} aria-label={groups.join(' ')}>
        {groups.map((group, index) => (
          <span key={index} className="enc-fingerprint__group">
            {group}
          </span>
        ))}
      </div>
    </div>
  );
}

/** Copy control for a fingerprint; swaps to a check for a moment once copied. */
export function CopyFingerprintButton({ fingerprint }: { fingerprint: string }) {
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

  return (
    <Button
      size="small"
      variant="tertiary"
      color={copied ? 'success' : 'neutral'}
      aria-label={copied ? t('identity.copied') : t('identity.copy_fingerprint')}
      title={copied ? t('identity.copied') : t('identity.copy_fingerprint')}
      icon={<Icon name={copied ? 'check' : 'content_copy'} size={16} />}
      onClick={copy}
    />
  );
}

interface IdentityCardProps {
  name: string;
  secondary?: string | null;
  fingerprint?: string | null;
  tone?: Tone;
  /** Top-right slot: a copy control by default when a fingerprint is shown. */
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
    <div className={tone === 'default' ? 'enc-card' : `enc-card enc-card--${tone}`}>
      <div className="enc-card__header">
        <Identity name={name} secondary={secondary} />
        {aside !== undefined ? aside : fingerprint ? <CopyFingerprintButton fingerprint={fingerprint} /> : null}
      </div>
      {fingerprint && <FingerprintBoxes fingerprint={fingerprint} tone={tone} />}
      {children}
    </div>
  );
}
