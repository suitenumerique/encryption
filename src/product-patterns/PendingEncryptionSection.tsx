import { Button, UserAvatar } from '@gouvfr-lasuite/ui-components';
import { Clock } from '@gouvfr-lasuite/ui-components/icons';

import { usePatternTranslate } from '@encryption/src/product-patterns/PatternProvider';
import { type PatternUser, me } from '@encryption/src/product-patterns/fixtures';

export interface PendingRow {
  user: PatternUser;
  /** The directory has a public key for them now. */
  hasPublicKey: boolean;
  accepting?: boolean;
}

// Members added to an encrypted item before they had encryption: the item's key
// could not be wrapped for them yet. A manager accepts the ones who have set it up
// since ("Action needed"); anyone else sees the list under "Waiting for access",
// each person waiting either for their own encryption or for a manager's acceptance.
export function PendingEncryptionSection({ rows, canAccept }: { rows: PendingRow[]; canAccept: boolean }) {
  const t = usePatternTranslate();

  if (rows.length === 0) {
    return null;
  }

  const someoneWaiting = rows.some((row) => !row.hasPublicKey);
  const title = t(canAccept && rows.some((row) => row.hasPublicKey) ? 'pendingTitle' : 'pendingWaitingTitle');

  return (
    <div className="c__share-modal__link-settings pp-pending" data-testid="pending-encryption">
      <div className="pp-pending__heading">
        <p className="c__share-modal__link-settings__title pp-pending__title">{title}</p>
        {someoneWaiting && <p className="pp-pending__hint">{t('pendingWaitingHint')}</p>}
      </div>
      <ul className="pp-pending__rows">
        {rows.map((row) => {
          const name = row.user.full_name || row.user.email;
          const label = row.user.id === me.id ? t('you', { name }) : name;
          const showAccept = canAccept && row.hasPublicKey;

          return (
            <li key={row.user.id} className="pp-pending__row">
              <div className="pp-pending__who">
                <UserAvatar fullName={name} size="small" />
                <div className="pp-pending__text">
                  <p className="c__user-row__name pp-pending__ellipsis" title={label}>
                    {label}
                  </p>
                  {row.user.full_name && (
                    <p className="c__user-row__email pp-pending__ellipsis" title={row.user.email}>
                      {row.user.email}
                    </p>
                  )}
                </div>
              </div>
              {showAccept ? (
                <Button size="small" variant="bordered" disabled={row.accepting}>
                  {row.accepting ? t('pendingAccepting') : t('pendingAccept')}
                </Button>
              ) : (
                <span className="pp-pending__chip" title={row.hasPublicKey ? t('pendingWaitingAcceptanceChipHint') : t('pendingWaitingChipHint')}>
                  <Clock aria-hidden size={16} />
                  {row.hasPublicKey ? t('pendingWaitingAcceptanceChip') : t('pendingWaitingChip')}
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
