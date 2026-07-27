import { MjmlButton, MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.emergencyRecoveryReminder';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface EmergencyRecoveryReminderEmailProps {
  locale: string;
  granteeEmail: string;
  daysRemaining: number;
  productUrl: string;
}

export function EmergencyRecoveryReminderEmail({ locale, granteeEmail, daysRemaining, productUrl }: EmergencyRecoveryReminderEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.intro`, { count: daysRemaining, granteeEmail })} />
        </p>
        <p>{t(locale, `${NS}.expected`)}</p>
        <p>
          <strong>{t(locale, `${NS}.unexpected`)}</strong>
        </p>
      </MjmlText>
      <MjmlButton href={productUrl}>{t(locale, `${NS}.button`)}</MjmlButton>
      <MjmlText></MjmlText>
    </StandardLayout>
  );
}
