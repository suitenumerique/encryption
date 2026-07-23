import { Button } from '@gouvfr-lasuite/cunningham-react';
import { useTranslation } from 'react-i18next';

import { type RecipientLabel } from '@encryption/src/shared/schemas/interface-context';
import { FingerprintDisplay } from '@encryption/src/ui/components/FingerprintDisplay';

/** The human-facing lines for a recipient, falling back to the raw userId. */
export function recipientLabel(label: RecipientLabel): { primary: string; secondary: string | null } {
  // No userId fallback: a raw OIDC sub tells a user nothing, and the product
  // always knows at least an email for someone it is sharing with.
  const primary = label.name || label.email;
  // Show the email underneath only when the primary line is the name (so we
  // never repeat the same value twice).
  const secondary = label.name && label.email ? label.email : null;

  return { primary, secondary };
}

/** Recipient identity block: name/email (or the raw userId when unlabelled). */
export function RecipientIdentity({ label }: { label: RecipientLabel }) {
  const { primary, secondary } = recipientLabel(label);

  return (
    <div style={{ marginBottom: 4 }}>
      <p style={{ fontSize: 13, fontWeight: 700, margin: 0, wordBreak: 'break-all' }}>{primary}</p>
      {secondary && (
        <p
          style={{
            fontSize: 12,
            margin: '2px 0 0',
            color: 'var(--c--contextuals--content--semantic--neutral--secondary, #666)',
            wordBreak: 'break-all',
          }}
        >
          {secondary}
        </p>
      )}
    </div>
  );
}

/** The recipient's 40-digit decimal identity fingerprint, formatted for reading out. */
export function RecipientFingerprint({ fingerprint }: { fingerprint: string }) {
  return (
    <div
      style={{
        fontFamily: 'monospace',
        fontSize: 16,
        letterSpacing: '0.05em',
        userSelect: 'all',
        padding: 'var(--c--globals--spacings--2, 8px)',
        background: 'var(--c--contextuals--background--surface--primary, #fff)',
        borderRadius: 4,
        marginBottom: 8,
        wordBreak: 'break-all',
      }}
    >
      <FingerprintDisplay fingerprint={fingerprint} />
    </div>
  );
}

/** Trust / Refuse action pair, shared by the verify modal and the profile view. */
export function TrustRefuseButtons({
  busy,
  onTrust,
  onRefuse,
  trustLabel,
  refuseLabel,
  size = 'small',
}: {
  busy: boolean;
  onTrust: () => void;
  onRefuse: () => void;
  trustLabel?: string;
  refuseLabel?: string;
  size?: 'small' | 'medium';
}) {
  const { t } = useTranslation('common');

  return (
    <div style={{ display: 'flex', gap: 8 }}>
      <Button size={size} disabled={busy} onClick={onTrust}>
        {trustLabel ?? t('verify.btn_trust')}
      </Button>
      <Button size={size} variant="secondary" color="error" disabled={busy} onClick={onRefuse}>
        {refuseLabel ?? t('verify.btn_refuse')}
      </Button>
    </div>
  );
}
