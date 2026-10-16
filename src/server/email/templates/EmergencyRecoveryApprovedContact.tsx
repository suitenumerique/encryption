import { MjmlButton, MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.emergencyRecoveryApprovedContact';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface EmergencyRecoveryApprovedContactEmailProps {
  locale: string;
  grantorEmail: string;
  productUrl: string;
}

export function EmergencyRecoveryApprovedContactEmail({ locale, grantorEmail, productUrl }: EmergencyRecoveryApprovedContactEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.body`, { grantorEmail })} />
        </p>
        <p>{t(locale, `${NS}.todo`)}</p>
        <p>{t(locale, `${NS}.privacy`)}</p>
      </MjmlText>
      <MjmlButton href={productUrl}>{t(locale, `${NS}.button`)}</MjmlButton>
      <MjmlText></MjmlText>
    </StandardLayout>
  );
}
