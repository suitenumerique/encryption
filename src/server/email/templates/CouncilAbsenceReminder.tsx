import { MjmlButton, MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.councilAbsenceReminder';

export function subject(locale: string): string {
  return t(locale, `${NS}.subject`);
}

export interface CouncilAbsenceReminderEmailProps {
  locale: string;
  council: string;
  absenceDays: number;
  productUrl: string;
}

export function CouncilAbsenceReminderEmail({ locale, council, absenceDays, productUrl }: CouncilAbsenceReminderEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.intro`, { council, count: absenceDays })} />
        </p>
        <p>{t(locale, `${NS}.action`)}</p>
      </MjmlText>
      <MjmlButton href={productUrl}>{t(locale, `${NS}.button`)}</MjmlButton>
      <MjmlText></MjmlText>
    </StandardLayout>
  );
}
