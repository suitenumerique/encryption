import { MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.emergencyVaultRecovered';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface EmergencyVaultRecoveredEmailProps {
  locale: string;
  granteeEmail: string;
}

export function EmergencyVaultRecoveredEmail({ locale, granteeEmail }: EmergencyVaultRecoveredEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>{t(locale, `${NS}.body`)}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.voided`, { granteeEmail })} />
        </p>
        <p>{t(locale, `${NS}.warning`)}</p>
      </MjmlText>
    </StandardLayout>
  );
}
