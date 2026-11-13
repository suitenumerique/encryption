import type { ReactNode } from 'react';

import { Identity } from '@encryption/src/ui/components/layout/IdentityCard';
import styles from '@encryption/src/ui/components/layout/layout.module.css';

/**
 * One person in a list (a trusted contact, a recovery request): who, their
 * status, a menu, and, under it, a tinted band for what their state asks of
 * the user, with its action.
 */
export function PersonRow({
  name,
  email,
  secondary,
  status,
  menu,
  band,
  bandTone = 'neutral',
}: {
  name: string;
  email: string;
  secondary?: string;
  status?: ReactNode;
  menu?: ReactNode;
  band?: ReactNode;
  bandTone?: 'neutral' | 'warning' | 'error';
}) {
  const bandClass = bandTone === 'error' ? styles.contactBandError : bandTone === 'warning' ? styles.contactBandWarning : '';

  return (
    <div className={styles.contact}>
      <div className={styles.contactMain}>
        <Identity name={name} email={email} secondary={secondary} />
        <div className={styles.cardAside}>
          {status}
          {menu}
        </div>
      </div>
      {band && <div className={`${styles.contactBand} ${bandClass}`}>{band}</div>}
    </div>
  );
}
