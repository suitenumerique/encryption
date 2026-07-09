import { Alert, Button, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { useTranslation } from 'react-i18next';

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
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          flexWrap: 'wrap',
        }}
      >
        <span style={{ flex: 1, minWidth: 0 }}>{t('errors.vault.session_expired')}</span>
        <Button size="small" onClick={onReconnect} disabled={isAuthenticating}>
          {isAuthenticating ? t('auth.authenticating', 'Signing in…') : t('auth.reconnect', 'Reconnect')}
        </Button>
      </div>
    </Alert>
  );
}
