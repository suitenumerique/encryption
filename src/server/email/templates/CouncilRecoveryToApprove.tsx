import { MjmlButton, MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.councilRecoveryToApprove';

/** `meet`: nobody has met the person yet (sent when they ask); `approve`: a custodian did, the others may approve remotely. */
export type CouncilRecoveryStep = 'meet' | 'approve';

export function subject(locale: string, step: CouncilRecoveryStep = 'approve'): string {
  return t(locale, step === 'meet' ? `${NS}.subject_meet` : `${NS}.subject`);
}

export interface CouncilRecoveryToApproveEmailProps {
  locale: string;
  requester: string;
  council: string;
  step: CouncilRecoveryStep;
  productUrl: string;
}

export function CouncilRecoveryToApproveEmail({ locale, requester, council, step, productUrl }: CouncilRecoveryToApproveEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale, step)}>
      <MjmlText>
        <h1>{t(locale, step === 'meet' ? `${NS}.title_meet` : `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.intro`, { requester, council })} />
        </p>
        <p>{t(locale, step === 'meet' ? `${NS}.meet` : `${NS}.met`)}</p>
      </MjmlText>
      <MjmlButton href={productUrl}>{t(locale, `${NS}.button`)}</MjmlButton>
      <MjmlText></MjmlText>
    </StandardLayout>
  );
}
