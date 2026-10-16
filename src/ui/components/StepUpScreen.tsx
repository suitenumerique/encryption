import { Alert, Button, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { useTranslation } from 'react-i18next';

import { Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';

interface StepUpScreenProps {
  /** Where the step-up stands (see useStepUp): only the two states that need the user are shown. */
  state: 'required' | 'no_second_factor';
  /** Wired to `oidcAuth.requestStepUp`: opens a new tab for a fresh second-factor sign-in. */
  onStepUp: () => void;
  /** True while that tab is open. Disables the button and swaps the label. */
  isAuthenticating?: boolean;
  /** What happens to the interrupted action once confirmed, in the words of the flow that needed it. */
  note?: string;
}

/**
 * Takes the place of a sensitive action's screen while the server refuses it for
 * want of a fresh second-factor authentication (RFC 9470 step-up): nothing else
 * can be done until the user confirms, so nothing else is offered.
 */
export function StepUpScreen({ state, onStepUp, isAuthenticating = false, note }: StepUpScreenProps) {
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
      banner={state === 'no_second_factor' && <Alert type={VariantType.ERROR}>{t('auth.step_up_no_second_factor')}</Alert>}
      actions={
        <>
          <Button onClick={onStepUp} disabled={isAuthenticating} fullWidth>
            {isAuthenticating ? t('auth.signing_in') : t(state === 'required' ? 'auth.step_up_confirm' : 'auth.step_up_retry')}
          </Button>
          {isAuthenticating && <p className={`${styles.hint} ${styles.hintCenter}`}>{t('auth.finish_in_tab')}</p>}
        </>
      }
    />
  );
}
