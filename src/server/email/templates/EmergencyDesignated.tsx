import { MjmlButton, MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.emergencyDesignated';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface EmergencyDesignatedEmailProps {
  locale: string;
  grantorEmail: string;
  waitTimeDays: number;
  productUrl: string;
}

export function EmergencyDesignatedEmail({ locale, grantorEmail, waitTimeDays, productUrl }: EmergencyDesignatedEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.intro`, { grantorEmail })} />
        </p>
        <p>{t(locale, `${NS}.role`, { waitTimeDays })}</p>
        <p>{t(locale, `${NS}.privacy`)}</p>
        <p>{t(locale, `${NS}.decline`)}</p>
      </MjmlText>
      <MjmlButton href={productUrl}>{t(locale, `${NS}.button`)}</MjmlButton>
      <MjmlText></MjmlText>
    </StandardLayout>
  );
}
