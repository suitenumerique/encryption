import { Button, Modal, ModalSize } from '@gouvfr-lasuite/ui-components';
import { Key } from '@gouvfr-lasuite/ui-components/icons';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import type { RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import { CopyFingerprintButton, FingerprintBoxes } from '@encryption/src/ui/components/layout/IdentityCard';
import { Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
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
        <Screen title={t('council.fingerprint_title')} description={t('council.custodian_code_hint')}>
          <div className={styles.section}>
            <FingerprintBoxes fingerprint={fingerprint} />
            <div>
              <CopyFingerprintButton fingerprint={fingerprint} />
            </div>
          </div>
        </Screen>
      </Modal>
    </>
  );
}
