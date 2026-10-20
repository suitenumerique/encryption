import { Button, Icon, UserAvatar } from '@gouvfr-lasuite/ui-components';

import { usePatternTranslate } from '@encryption/src/product-patterns/PatternProvider';
import type { PatternUser } from '@encryption/src/product-patterns/fixtures';

export interface DocsPendingRow {
  user: PatternUser;
  /**
   * `ready`: they have enabled encryption since, Accept wraps the key for them.
   * `waiting`: they still have no key, so there is nothing to accept yet.
   * `accepting`: the Accept click is in flight.
   */
  status: 'ready' | 'waiting' | 'accepting';
  error?: 'not-onboarded' | 'wrap-failed';
}

// PendingEncryptionSection.tsx (Docs): members added to the encrypted document
// before they had encryption, above the member list, for whoever manages
// members. useAutoAcceptPendingMembers.tsx accepts the ready ones by itself when
// such a person opens the document, so this list is the manual fallback.
export function DocsPendingEncryptionSection({ rows }: { rows: DocsPendingRow[] }) {
  const t = usePatternTranslate();

  if (rows.length === 0) {
    return null;
  }

  const someoneWaiting = rows.some((row) => row.status === 'waiting');

  return (
    <section className="pp-docs-pending" data-testid="docs-pending-encryption" aria-label={t('docsActionNeeded')}>
      <div className="pp-docs-pending__heading">
        <span className="pp-docs-pending__title">{t('docsActionNeeded')}</span>
        {someoneWaiting && <span className="pp-docs-pending__hint">{t('docsWaitingHint')}</span>}
      </div>
      <ul className="pp-docs-pending__rows">
        {rows.map((row) => {
          const name = row.user.full_name || row.user.email;

          return (
            <li key={row.user.id} className="pp-docs-pending__row">
              <div className="pp-docs-pending__who">
                <UserAvatar fullName={name} size="small" />
                <div className="pp-docs-pending__text">
                  <span className="pp-docs-pending__name">{name}</span>
                  {row.user.full_name && <span className="pp-docs-pending__email">{row.user.email}</span>}
                  {row.error && (
                    <span className="pp-docs-pending__error">
                      {row.error === 'not-onboarded' ? t('docsNotOnboardedError') : t('docsWrapFailedError')}
                    </span>
                  )}
                </div>
              </div>
              {row.status === 'waiting' ? (
                <span className="pp-docs-pending__chip" title={t('docsWaitingChipTitle')}>
                  <Icon name="schedule" size={16} />
                  {t('docsWaitingForEncryption')}
                </span>
              ) : (
                <Button size="small" variant="bordered" disabled={row.status === 'accepting'}>
                  {row.status === 'accepting' ? t('docsAccepting') : t('docsAccept')}
                </Button>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
