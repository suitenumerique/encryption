import { Button, VariantType } from '@gouvfr-lasuite/ui-components';
import { useTranslation } from 'react-i18next';

import { Notice } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';

interface SessionExpiredAlertProps {
  /** Wired to `oidcAuth.requestAuth`: opens a new tab to /login. */
  onReconnect: () => void;
  /**
   * True while a sign-in tab is out. The button then opens the sign-in again:
   * the iframe cannot tell whether that tab is still there.
   */
  isAuthenticating?: boolean;
  /** Wired to `oidcAuth.cancelAuth`: stops waiting for that tab. */
  onCancel?: () => void;
}

/**
 * Renders the "your session expired, reconnect to continue" banner used
 * by any iframe handler that hit `SessionExpiredError`. See
 * `auth/session-expired.ts` for the overall pattern.
 */
export function SessionExpiredAlert({ onReconnect, isAuthenticating = false, onCancel }: SessionExpiredAlertProps) {
  const { t } = useTranslation('common');
  return (
    <Notice type={VariantType.ERROR}>
      <div className={styles.alertStack}>
        <span>{t('errors.vault.session_expired')}</span>
        <div>
          <Button size="nano" onClick={onReconnect}>
            {isAuthenticating ? t('auth.reopen') : t('auth.reconnect')}
          </Button>
          {isAuthenticating && onCancel && (
            <Button size="nano" variant="bordered" color="neutral" onClick={onCancel}>
              {t('auth.cancel')}
            </Button>
          )}
        </div>
        {isAuthenticating && <span className={styles.hint}>{t('auth.finish_in_tab')}</span>}
      </div>
    </Notice>
  );
}
