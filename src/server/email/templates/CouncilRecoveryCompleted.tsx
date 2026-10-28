import { MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.councilRecoveryCompleted';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface CouncilRecoveryCompletedEmailProps {
  locale: string;
  council: string;
  contributors: string;
}

export function CouncilRecoveryCompletedEmail({ locale, council, contributors }: CouncilRecoveryCompletedEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.intro`, { council, contributors })} />
        </p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.who`, { council, contributors })} />
        </p>
        <p>{t(locale, `${NS}.next`)}</p>
      </MjmlText>
    </StandardLayout>
  );
}
