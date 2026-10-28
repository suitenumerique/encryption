import { MjmlButton, MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.councilRecoveryMeeting';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface CouncilRecoveryMeetingEmailProps {
  locale: string;
  council: string;
  custodians: string;
  productUrl: string;
}

export function CouncilRecoveryMeetingEmail({ locale, council, custodians, productUrl }: CouncilRecoveryMeetingEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.intro`, { council, custodians })} />
        </p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.who`, { council, custodians })} />
        </p>
        <p>{t(locale, `${NS}.screen`)}</p>
      </MjmlText>
      <MjmlButton href={productUrl}>{t(locale, `${NS}.button`)}</MjmlButton>
      <MjmlText></MjmlText>
    </StandardLayout>
  );
}
