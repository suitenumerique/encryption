import { MjmlButton, MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.councilRecoveryRequested';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface CouncilRecoveryRequestedEmailProps {
  locale: string;
  council: string;
  productUrl: string;
}

export function CouncilRecoveryRequestedEmail({ locale, council, productUrl }: CouncilRecoveryRequestedEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.intro`, { council })} />
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
