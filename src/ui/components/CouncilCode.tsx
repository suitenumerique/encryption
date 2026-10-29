import { Button, Modal, ModalSize } from '@gouvfr-lasuite/ui-components';
import { Checkmark2, Copy, Key } from '@gouvfr-lasuite/ui-components/icons';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { normalizeDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';
import type { RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import { FingerprintBoxes } from '@encryption/src/ui/components/layout/IdentityCard';
import { Screen } from '@encryption/src/ui/components/layout/Screen';
import { useCouncilVault } from '@encryption/src/ui/hooks/useCouncilVault';

/**
 * The council's code (its version 1) as the custodian's vault computes it from
 * the chain it verified: what the organization publishes once for its users.
 * Rarely needed, so a small button opening it in a dialog; nothing is shown for
 * a chain that does not verify.
 */
export function CouncilCode({ councilId, chain }: { councilId: string; chain: RosterVersionWire[] }) {
  const { t } = useTranslation('common');
  const vault = useCouncilVault();
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;

    vault
      .verifyRoster(councilId, chain)
      .then((identity) => {
        if (!cancelled) setFingerprint(identity.fingerprint);
      })
      .catch(() => {
        if (!cancelled) setFingerprint(null);
      });

    return () => {
      cancelled = true;
    };
  }, [vault, councilId, chain]);

  if (!fingerprint) return null;

  return (
    <>
      <Button size="nano" variant="bordered" color="neutral" icon={<Key aria-hidden size={16} />} onClick={() => setOpen(true)}>
        {t('council.fingerprint_title')}
      </Button>
      <Modal isOpen={open} onClose={() => setOpen(false)} size={ModalSize.MEDIUM} aria-label={t('council.fingerprint_title')}>
        <Screen
          title={t('council.fingerprint_title')}
          description={t('council.custodian_code_hint')}
          actions={<CopyButton text={normalizeDecimalFingerprint(fingerprint)} />}
        >
          <FingerprintBoxes fingerprint={fingerprint} />
        </Screen>
      </Modal>
    </>
  );
}

/** The dialog's one action: copying the code, for the page or email that publishes it. */
function CopyButton({ text }: { text: string }) {
  const { t } = useTranslation('common');
  const [copied, setCopied] = useState(false);

  return (
    <Button
      variant="bordered"
      color={copied ? 'success' : 'neutral'}
      icon={copied ? <Checkmark2 aria-hidden size={16} /> : <Copy aria-hidden size={16} />}
      onClick={() => {
        void navigator.clipboard
          .writeText(text)
          .then(() => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
          })
          // Clipboard may be unavailable inside a sandboxed iframe.
          .catch(() => {});
      }}
    >
      {copied ? t('device_approval.copied') : t('council.copy_code')}
    </Button>
  );
}
