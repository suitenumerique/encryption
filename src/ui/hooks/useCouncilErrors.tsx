import { Button, VariantType } from '@gouvfr-lasuite/ui-components';
import { type ReactNode, useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { SessionExpiredError, StepUpRequiredError } from '@encryption/src/ui/auth/session-expired';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
import { Notice } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { useSessionExpired } from '@encryption/src/ui/hooks/useSessionExpired';

export interface CouncilAuthProps {
  onReconnect?: () => void;
  /** Wired to `oidcAuth.requestStepUp`: a fresh second-factor sign-in, which custodian actions require. */
  onStepUp?: () => void;
  isAuthenticating?: boolean;
  onCancelAuth?: () => void;
  currentIdToken?: string | null;
}

/**
 * The failures every council screen shows the same way, above its body: a lapsed
 * session (Reconnect), a custodian action refused for want of a fresh second
 * factor (Confirm my identity), or the message of anything else.
 */
export function useCouncilErrors({ onReconnect, onStepUp, isAuthenticating = false, onCancelAuth, currentIdToken = null }: CouncilAuthProps) {
  const { t } = useTranslation('common');
  const { sessionExpired, markSessionExpired, clearSessionExpired } = useSessionExpired(currentIdToken, isAuthenticating);
  const [stepUp, setStepUp] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const clear = useCallback(() => {
    clearSessionExpired();
    setStepUp(false);
    setMessage(null);
  }, [clearSessionExpired]);

  const fail = useCallback(
    (err: unknown) => {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else if (err instanceof StepUpRequiredError) setStepUp(true);
      else setMessage(err instanceof Error ? err.message : String(err));
    },
    [markSessionExpired]
  );

  let banner: ReactNode = null;

  if (sessionExpired && onReconnect) {
    banner = <SessionExpiredAlert onReconnect={onReconnect} isAuthenticating={isAuthenticating} onCancel={onCancelAuth} />;
  } else if (stepUp) {
    banner = (
      <Notice type={VariantType.WARNING}>
        <div className={styles.alertStack}>
          <span>{t('council.step_up_required')}</span>
          {onStepUp && (
            <div>
              <Button size="nano" color="warning" onClick={onStepUp}>
                {isAuthenticating ? t('auth.reopen') : t('auth.step_up_confirm')}
              </Button>
            </div>
          )}
        </div>
      </Notice>
    );
  } else if (message) {
    banner = <Notice type={VariantType.ERROR}>{message}</Notice>;
  }

  return { banner, fail, clear };
}
