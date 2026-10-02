import { Button } from '@gouvfr-lasuite/cunningham-react';
import { useTranslation } from 'react-i18next';

import { type RecipientLabel } from '@encryption/src/shared/schemas/interface-context';
import { Actions } from '@encryption/src/ui/components/layout/Screen';

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

/** "Don't trust" / "Trust" pair, shared by the verify modal and the profile view. */
export function TrustRefuseButtons({
  busy,
  onTrust,
  onRefuse,
  trustLabel,
  refuseLabel,
}: {
  busy: boolean;
  onTrust: () => void;
  onRefuse: () => void;
  trustLabel?: string;
  refuseLabel?: string;
}) {
  const { t } = useTranslation('common');

  return (
    <Actions layout="row">
      <Button variant="bordered" color="error" disabled={busy} onClick={onRefuse}>
        {refuseLabel ?? t('verify.btn_refuse')}
      </Button>
      <Button disabled={busy} onClick={onTrust}>
        {trustLabel ?? t('verify.btn_trust')}
      </Button>
    </Actions>
  );
}
