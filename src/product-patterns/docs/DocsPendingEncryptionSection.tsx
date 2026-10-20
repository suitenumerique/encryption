import { Button, Icon, UserAvatar } from '@gouvfr-lasuite/ui-components';

import { usePatternTranslate } from '@encryption/src/product-patterns/PatternProvider';
import type { PatternUser } from '@encryption/src/product-patterns/fixtures';

export interface DocsPendingRow {
  user: PatternUser;
  /** The directory has a public key for them now: they enabled encryption since. */
  hasPublicKey: boolean;
  /** The Accept click is in flight. */
  accepting?: boolean;
  error?: 'not-onboarded' | 'wrap-failed';
}

// PendingEncryptionSection.tsx (Docs): members added to the encrypted document
// before they had encryption, above the member list, for anyone who can view
// the members (the member list itself says nothing about them). A manager
// (`canAccept`) gets Accept for the ones who are ready; anyone else sees
// "Encryption enabled" for them. useAutoAcceptPendingMembers.tsx accepts the
// ready ones by itself when a manager opens the document, so this list is
// mostly the manual fallback.
export function DocsPendingEncryptionSection({ rows, canAccept }: { rows: DocsPendingRow[]; canAccept: boolean }) {
  const t = usePatternTranslate();

  if (rows.length === 0) {
    return null;
  }

  const someoneWaiting = rows.some((row) => !row.hasPublicKey);

  return (
    <section className="pp-docs-pending" data-testid="docs-pending-encryption" aria-label={t('docsActionNeeded')}>
      <div className="pp-docs-pending__heading">
        <span className="pp-docs-pending__title">{t('docsActionNeeded')}</span>
        {someoneWaiting && <span className="pp-docs-pending__hint">{t('docsWaitingHint')}</span>}
      </div>
      <ul className="pp-docs-pending__rows">
        {rows.map((row) => {
          const name = row.user.full_name || row.user.email;
          const showAccept = canAccept && row.hasPublicKey;

          return (
            <li key={row.user.id} className="pp-docs-pending__row">
              <div className="pp-docs-pending__who">
                <UserAvatar fullName={name} size="small" />
                <div className="pp-docs-pending__text">
                  <span className="pp-docs-pending__name">{name}</span>
                  {row.user.full_name && <span className="pp-docs-pending__email">{row.user.email}</span>}
                  {row.hasPublicKey && !showAccept && (
                    <span className="pp-docs-pending__enabled">
                      <Icon name="verified_user" size={16} />
                      {t('docsEncryptionEnabled')}
                    </span>
                  )}
                  {row.error && (
                    <span className="pp-docs-pending__error">
                      {row.error === 'not-onboarded' ? t('docsNotOnboardedError') : t('docsWrapFailedError')}
                    </span>
                  )}
                </div>
              </div>
              {showAccept && (
                <Button size="small" variant="bordered" disabled={row.accepting}>
                  {row.accepting ? t('docsAccepting') : t('docsAccept')}
                </Button>
              )}
              {!row.hasPublicKey && (
                <span className="pp-docs-pending__chip" title={t('docsWaitingChipTitle')}>
                  <Icon name="schedule" size={16} />
                  {t('docsWaitingForEncryption')}
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
