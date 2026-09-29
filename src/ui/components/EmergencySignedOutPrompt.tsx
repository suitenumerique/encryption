import { Button } from '@gouvfr-lasuite/cunningham-react';
import { useTranslation } from 'react-i18next';

import { Screen } from '@encryption/src/ui/components/layout/Screen';

export interface EmergencySignedOutPromptProps {
  recovery: boolean;
  onSignIn: () => void;
}

/**
 * The emergency prompt the SDK opens on its own, while the interface has no session.
 * The vault's signal already says what is pending (a recovery request against the
 * user's data, or an invitation), so it is said at once; who, when, and acting on it
 * need the session. A recovery request leads when both are pending.
 */
export function EmergencySignedOutPrompt({ recovery, onSignIn }: EmergencySignedOutPromptProps) {
  const { t } = useTranslation('common');

  return (
    <Screen
      illustration={recovery ? 'shield-x' : 'shield-check'}
      title={t(recovery ? 'emergency.prompt_recovery_title' : 'emergency.prompt_invite_title')}
      description={t(recovery ? 'emergency.prompt_signed_out_recovery' : 'emergency.prompt_signed_out_invite')}
      actions={<Button onClick={onSignIn}>{t('emergency.btn_prompt_sign_in')}</Button>}
    />
  );
}
