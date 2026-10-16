import { MjmlButton, MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.emergencyRecoveryApprovedGrantor';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface EmergencyRecoveryApprovedGrantorEmailProps {
  locale: string;
  granteeEmail: string;
  productUrl: string;
}

export function EmergencyRecoveryApprovedGrantorEmail({ locale, granteeEmail, productUrl }: EmergencyRecoveryApprovedGrantorEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.body`, { granteeEmail })} />
        </p>
        <p>{t(locale, `${NS}.meaning`)}</p>
        <p>{t(locale, `${NS}.revoke`)}</p>
      </MjmlText>
      <MjmlButton href={productUrl}>{t(locale, `${NS}.button`)}</MjmlButton>
      <MjmlText></MjmlText>
    </StandardLayout>
  );
}
