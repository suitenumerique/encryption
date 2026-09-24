import { Alert, Button, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { useTranslation } from 'react-i18next';

import styles from '@encryption/src/ui/components/layout/layout.module.css';

interface SessionExpiredAlertProps {
  /** Wired to `oidcAuth.requestAuth` — opens a new tab to /login. */
  onReconnect: () => void;
  /**
   * True while the login tab is open and we're awaiting the token
   * postMessage back. Disables the button and swaps the label.
   */
  isAuthenticating?: boolean;
}

/**
 * Renders the "your session expired, reconnect to continue" banner used
 * by any iframe handler that hit `SessionExpiredError`. See
 * `auth/session-expired.ts` for the overall pattern.
 */
export function SessionExpiredAlert({ onReconnect, isAuthenticating = false }: SessionExpiredAlertProps) {
  const { t } = useTranslation('common');
  return (
    <Alert type={VariantType.ERROR}>
      <div className={styles.alertStack}>
        <span>{t('errors.vault.session_expired')}</span>
        <div>
          <Button size="small" onClick={onReconnect} disabled={isAuthenticating}>
            {isAuthenticating ? t('auth.signing_in') : t('auth.reconnect')}
          </Button>
        </div>
        {isAuthenticating && <span className={styles.hint}>{t('auth.finish_in_tab')}</span>}
      </div>
    </Alert>
  );
}
