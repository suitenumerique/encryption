import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import type { RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import { CopyFingerprintButton, FingerprintBoxes } from '@encryption/src/ui/components/layout/IdentityCard';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { useCouncilVault } from '@encryption/src/ui/hooks/useCouncilVault';

/**
 * The council's code (its version 1) as the custodian's vault computes it from
 * the chain it verified: what the organization publishes once for its users.
 * Nothing is shown for a chain that does not verify.
 */
export function CouncilCode({ councilId, chain }: { councilId: string; chain: RosterVersionWire[] }) {
  const { t } = useTranslation('common');
  const vault = useCouncilVault();
  const [fingerprint, setFingerprint] = useState<string | null>(null);

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
    <div className={styles.section}>
      <div className={styles.cardHeader}>
        <p className={styles.sectionTitle}>{t('council.fingerprint_title')}</p>
        <CopyFingerprintButton fingerprint={fingerprint} />
      </div>
      <p className={styles.hint}>{t('council.custodian_code_hint')}</p>
      <FingerprintBoxes fingerprint={fingerprint} />
    </div>
  );
}
