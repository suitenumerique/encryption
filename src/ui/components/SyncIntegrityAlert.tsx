import { Alert, Button, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { useTranslation } from 'react-i18next';

import styles from '@encryption/src/ui/components/layout/layout.module.css';

interface SyncIntegrityAlertProps {
  /** Runs another full sync; the alert disappears once the server copy verifies. */
  onRetry: () => void;
  isRetrying?: boolean;
}

/**
 * Shown in the settings when the vault stored on the server still fails its
 * integrity check after the automatic retry. Not blocking: the device keeps
 * working on its last verified copy, only syncing is paused.
 */
export function SyncIntegrityAlert({ onRetry, isRetrying = false }: SyncIntegrityAlertProps) {
  const { t } = useTranslation('common');

  return (
    <Alert type={VariantType.WARNING}>
      <div className={styles.alertStack}>
        <span>{t('settings.sync_integrity_failed')}</span>
        <div>
          <Button size="small" variant="secondary" onClick={onRetry} disabled={isRetrying}>
            {isRetrying ? t('settings.sync_integrity_retrying') : t('settings.sync_integrity_retry')}
          </Button>
        </div>
      </div>
    </Alert>
  );
}
