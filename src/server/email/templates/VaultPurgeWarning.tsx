import { MjmlButton, MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.vaultPurgeWarning';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface VaultPurgeWarningEmailProps {
  locale: string;
  disabledAtMillis: number;
  purgeAtMillis: number;
  productUrl: string;
}

export function VaultPurgeWarningEmail({ locale, disabledAtMillis, purgeAtMillis, productUrl }: VaultPurgeWarningEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.intro`, { disabledAt: new Date(disabledAtMillis) })} />
        </p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.deadline`, { purgeAt: new Date(purgeAtMillis) })} />
        </p>
        <p>{t(locale, `${NS}.keep`)}</p>
        <p>{t(locale, `${NS}.nothing`)}</p>
      </MjmlText>
      <MjmlButton href={productUrl}>{t(locale, `${NS}.button`)}</MjmlButton>
      <MjmlText></MjmlText>
    </StandardLayout>
  );
}
