import { MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.vaultPurged';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface VaultPurgedEmailProps {
  locale: string;
  disabledAtMillis: number;
}

export function VaultPurgedEmail({ locale, disabledAtMillis }: VaultPurgedEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.intro`, { disabledAt: new Date(disabledAtMillis) })} />
        </p>
        <p>{t(locale, `${NS}.consequence`)}</p>
      </MjmlText>
    </StandardLayout>
  );
}
