import { MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.emergencyRecoveryRejected';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface EmergencyRecoveryRejectedEmailProps {
  locale: string;
  grantor: string;
}

export function EmergencyRecoveryRejectedEmail({ locale, grantor }: EmergencyRecoveryRejectedEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.body`, { grantor })} />
        </p>
        <p>{t(locale, `${NS}.note`)}</p>
      </MjmlText>
    </StandardLayout>
  );
}
