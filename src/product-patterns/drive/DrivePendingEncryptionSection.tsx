import { Button, Icon, UserAvatar } from '@gouvfr-lasuite/ui-components';

import { usePatternTranslate } from '@encryption/src/product-patterns/PatternProvider';
import type { PatternUser } from '@encryption/src/product-patterns/fixtures';

export interface DrivePendingRow {
  user: PatternUser;
  /** The directory has a public key for them now. */
  hasPublicKey: boolean;
  accepting?: boolean;
  error?: boolean;
}

// encryption/sharing/PendingEncryptionSection.tsx (Drive), rendered in the
// share modal's `outsideSearchContent`, above the copy-link footer. Unlike
// Docs, a viewer who may not accept still sees the list, with "Encryption
// enabled" for the members who are ready.
export function DrivePendingEncryptionSection({ rows, canAccept }: { rows: DrivePendingRow[]; canAccept: boolean }) {
  const t = usePatternTranslate();

  if (rows.length === 0) {
    return null;
  }

  const someoneWaiting = rows.some((row) => !row.hasPublicKey);

  return (
    <div className="c__share-modal__link-settings pp-drive-pending" data-testid="drive-pending-encryption">
      <div className="pp-drive-pending__heading">
        <p className="c__share-modal__link-settings__title pp-drive-pending__title">{t('drivePendingTitle')}</p>
        {someoneWaiting && <p className="pp-drive-pending__hint">{t('drivePendingWaitingHint')}</p>}
      </div>
      <ul className="pp-drive-pending__rows">
        {rows.map((row) => {
          const name = row.user.full_name || row.user.email;
          const showAccept = canAccept && row.hasPublicKey;

          return (
            <li key={row.user.id} className="pp-drive-pending__row">
              <div className="pp-drive-pending__who">
                <UserAvatar fullName={name} size="small" />
                <div className="pp-drive-pending__text">
                  <p className="c__user-row__name pp-drive-pending__ellipsis" title={name}>
                    {name}
                  </p>
                  {row.user.full_name && (
                    <p className="c__user-row__email pp-drive-pending__ellipsis" title={row.user.email}>
                      {row.user.email}
                    </p>
                  )}
                  {row.hasPublicKey && !showAccept && (
                    <p className="pp-drive-pending__enabled">
                      <Icon aria-hidden name="verified_user" size={14} />
                      {t('drivePendingEncryptionEnabled')}
                    </p>
                  )}
                  {row.error && <p className="pp-drive-pending__error">{t('drivePendingNoPublicKey')}</p>}
                </div>
              </div>
              {showAccept ? (
                <Button size="small" variant="bordered" disabled={row.accepting}>
                  {row.accepting ? t('drivePendingAccepting') : t('drivePendingAccept')}
                </Button>
              ) : row.hasPublicKey ? null : (
                <span className="pp-drive-pending__chip" title={t('drivePendingWaitingChipHint')}>
                  <Icon aria-hidden name="schedule" size={16} />
                  {t('drivePendingWaitingChip')}
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
