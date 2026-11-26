import { MjmlButton, MjmlText } from '@faire/mjml-react';

import { EmailHtml } from '@encryption/src/server/email/EmailHtml';
import { StandardLayout } from '@encryption/src/server/email/layout';
import { t, tHtml } from '@encryption/src/server/i18n';

const NS = 'emails.councilHealthAlert';

export type CouncilHealthAlertStatus = 'blocked' | 'at-risk' | 'lost';

function variant(status: CouncilHealthAlertStatus): 'blocked' | 'atRisk' | 'lost' {
  return status === 'at-risk' ? 'atRisk' : status;
}

const list = (locale: string, names: string[]) => new Intl.ListFormat(locale, { type: 'conjunction' }).format(names);

export function subject(locale: string, status: CouncilHealthAlertStatus): string {
  return t(locale, `${NS}.${variant(status)}.subject`);
}

export interface CouncilHealthAlertEmailProps {
  locale: string;
  council: string;
  status: CouncilHealthAlertStatus;
  /** People the team can no longer give their access back. */
  lost: number;
  /** Custodians without a sign-in for `absenceDays`. */
  absent: string[];
  /** Custodians who no longer have encryption set up. */
  inactive: string[];
  /** Every custodian has encryption set up: the people lost can join again now. */
  teamReady: boolean;
  absenceDays: number;
  productUrl: string;
}

export function CouncilHealthAlertEmail({
  locale,
  council,
  status,
  lost,
  absent,
  inactive,
  teamReady,
  absenceDays,
  productUrl,
}: CouncilHealthAlertEmailProps) {
  return (
    <StandardLayout locale={locale} title={subject(locale, status)}>
      <MjmlText>
        <h1>{t(locale, `${NS}.${variant(status)}.title`)}</h1>
        <p>{t(locale, 'emails.hello')}</p>
        <p>
          <EmailHtml html={tHtml(locale, `${NS}.${variant(status)}.intro`, { council })} />
        </p>
        {inactive.length > 0 && (
          <p>
            {t(locale, `${NS}.inactive`, { count: inactive.length, names: list(locale, inactive) })}
            {/* The blocked variant says it in its intro already. */}
            {status !== 'blocked' && ` ${t(locale, `${NS}.inactive_no_join`)}`}
          </p>
        )}
        {absent.length > 0 && <p>{t(locale, `${NS}.absent`, { count: absenceDays, names: list(locale, absent) })}</p>}
        {lost > 0 && <p>{t(locale, teamReady ? `${NS}.lost_people` : `${NS}.lost_people_repair`, { count: lost })}</p>}
        <p>{t(locale, `${NS}.action`)}</p>
      </MjmlText>
      <MjmlButton href={productUrl}>{t(locale, `${NS}.button`)}</MjmlButton>
      <MjmlText></MjmlText>
    </StandardLayout>
  );
}
