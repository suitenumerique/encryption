import { MjmlButton, MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.emergencyRecoveryRequested';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface EmergencyRecoveryRequestedEmailProps {
  locale: string;
  granteeEmail: string;
  waitTimeDays: number;
  deadlineMillis: number;
  productUrl: string;
}

export function EmergencyRecoveryRequestedEmail({
  locale,
  granteeEmail,
  waitTimeDays,
  deadlineMillis,
  productUrl,
}: EmergencyRecoveryRequestedEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.intro`, { granteeEmail })} />
        </p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.deadline`, { deadline: new Date(deadlineMillis), waitTimeDays })} />
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
