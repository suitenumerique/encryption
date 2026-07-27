import { MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.emergencyRecoveryCancelled';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface EmergencyRecoveryCancelledEmailProps {
  locale: string;
  granteeEmail: string;
}

export function EmergencyRecoveryCancelledEmail({ locale, granteeEmail }: EmergencyRecoveryCancelledEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.body`, { granteeEmail })} />
        </p>
        <p>{t(locale, `${NS}.note`)}</p>
      </MjmlText>
    </StandardLayout>
  );
}
