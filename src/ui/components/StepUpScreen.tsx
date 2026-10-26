import { Button, VariantType } from '@gouvfr-lasuite/ui-components';
import { useTranslation } from 'react-i18next';

import { Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';

interface StepUpScreenProps {
  /** Where the step-up stands (see useStepUp): only the two states that need the user are shown. */
  state: 'required' | 'no_second_factor';
  /** Wired to `oidcAuth.requestStepUp`: opens a new tab for a fresh second-factor sign-in. */
  onStepUp: () => void;
  /** True while that tab is out: the button then opens it again. */
  isAuthenticating?: boolean;
  /** Wired to `oidcAuth.cancelAuth`: stops waiting for that tab. */
  onCancel?: () => void;
  /** What happens to the interrupted action once confirmed, in the words of the flow that needed it. */
  note?: string;
}

/**
 * Takes the place of a sensitive action's screen while the server refuses it for
 * want of a fresh second-factor authentication (RFC 9470 step-up): nothing else
 * can be done until the user confirms, so nothing else is offered.
 */
export function StepUpScreen({ state, onStepUp, isAuthenticating = false, onCancel, note }: StepUpScreenProps) {
  const { t } = useTranslation('common');

  return (
    <Screen
      title={t('auth.step_up_title')}
      description={
        <>
          <p>{t('auth.step_up_required')}</p>
          {note && <p>{note}</p>}
        </>
      }
      banner={state === 'no_second_factor' && <Notice type={VariantType.ERROR}>{t('auth.step_up_no_second_factor')}</Notice>}
      actions={
        <>
          <Button onClick={onStepUp} fullWidth>
            {isAuthenticating ? t('auth.reopen') : t(state === 'required' ? 'auth.step_up_confirm' : 'auth.step_up_retry')}
          </Button>
          {isAuthenticating && onCancel && (
            <Button variant="bordered" color="neutral" onClick={onCancel} fullWidth>
              {t('auth.cancel')}
            </Button>
          )}
          {isAuthenticating && <p className={`${styles.hint} ${styles.hintCenter}`}>{t('auth.finish_in_tab')}</p>}
        </>
      }
    />
  );
}
