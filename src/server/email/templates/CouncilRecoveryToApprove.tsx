import { MjmlButton, MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.councilRecoveryToApprove';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface CouncilRecoveryToApproveEmailProps {
  locale: string;
  requester: string;
  council: string;
  productUrl: string;
}

export function CouncilRecoveryToApproveEmail({ locale, requester, council, productUrl }: CouncilRecoveryToApproveEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.intro`, { requester, council })} />
        </p>
        <p>{t(locale, `${NS}.remote`)}</p>
        <p>{t(locale, `${NS}.meeting`)}</p>
      </MjmlText>
      <MjmlButton href={productUrl}>{t(locale, `${NS}.button`)}</MjmlButton>
      <MjmlText></MjmlText>
    </StandardLayout>
  );
}
