import { MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.councilRecoveryReady';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface CouncilRecoveryReadyEmailProps {
  locale: string;
  council: string;
}

/** No button: only the browser that asked can combine the parts, so a link opened elsewhere would mislead. */
export function CouncilRecoveryReadyEmail({ locale, council }: CouncilRecoveryReadyEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.intro`, { council })} />
        </p>
        <p>{t(locale, `${NS}.where`)}</p>
        <p>{t(locale, `${NS}.next`)}</p>
      </MjmlText>
    </StandardLayout>
  );
}
