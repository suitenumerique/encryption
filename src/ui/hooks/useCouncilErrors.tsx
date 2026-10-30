import { Button, VariantType } from '@gouvfr-lasuite/ui-components';
import { type ReactNode, useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { VaultErrorCode, isVaultError } from '@encryption/src/shared/vault-error';
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

type CouncilVaultErrorKey =
  | 'errors.vault.council_integrity_failed'
  | 'errors.vault.council_untrusted'
  | 'errors.vault.council_code_mismatch'
  | 'errors.vault.council_no_request'
  | 'errors.vault.council_meeting_first'
  | 'errors.vault.request_timeout'
  | 'errors.unknown';

/** The vault's message is English and meant for logs: the person reads a translation of its code. */
export function councilVaultErrorKey(code: VaultErrorCode): CouncilVaultErrorKey {
  switch (code) {
    case VaultErrorCode.VAULT_INTEGRITY_FAILED:
      return 'errors.vault.council_integrity_failed';
    case VaultErrorCode.UNTRUSTED_RECIPIENT:
      return 'errors.vault.council_untrusted';
    case VaultErrorCode.INVALID_KEY_BINDING:
      return 'errors.vault.council_code_mismatch';
    case VaultErrorCode.NOT_INITIALIZED:
      return 'errors.vault.council_no_request';
    case VaultErrorCode.COUNCIL_MEETING_FIRST:
      return 'errors.vault.council_meeting_first';
    case VaultErrorCode.TIMEOUT:
      return 'errors.vault.request_timeout';
    default:
      return 'errors.unknown';
  }
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
      else if (isVaultError(err)) setMessage(t(councilVaultErrorKey(err.code)));
      else setMessage(err instanceof Error ? err.message : String(err));
    },
    [markSessionExpired, t]
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
