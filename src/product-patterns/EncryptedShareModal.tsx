import {
  type AccessData,
  Button,
  ConfirmationModal,
  HorizontalSeparator,
  Modal,
  ModalSize,
  ShareModal,
  ShareModalCopyLinkFooter,
  type UserData,
  UserRow,
} from '@gouvfr-lasuite/ui-components';
import { useState } from 'react';

import { usePatternTranslate } from '@encryption/src/product-patterns/PatternProvider';
import { PendingEncryptionSection, type PendingRow } from '@encryption/src/product-patterns/PendingEncryptionSection';
import { type PatternUser, me } from '@encryption/src/product-patterns/fixtures';

// The share modal of an encrypted item, on the design system's ShareModal.
// Encryption adds what the modal leaves room for: in `outsideSearchContent`, the
// pending members and, for a viewer without encryption on this device, why some
// actions are gone; and a dialog before inviting (the modal draws its search
// results itself, with no room for a mark next to a name). An encrypted item has
// no link settings: it stays restricted, so its members are the only way in.

type Role = 'reader' | 'editor' | 'administrator' | 'owner';

const ROLES: Role[] = ['reader', 'editor', 'administrator', 'owner'];

export interface Member {
  user: PatternUser;
  role: Role;
}

export interface SearchResult {
  user: PatternUser;
  /** The directory has a public key for them. */
  hasKeys: boolean;
}

export interface EncryptedShareModalProps {
  itemTitle: string;
  members: Member[];
  pending?: PendingRow[];
  /** What a search answers, whatever is typed. */
  searchResults?: SearchResult[];
  /** The viewer may manage members, and so accept the pending ones. */
  canManage?: boolean;
  /** The viewer has encryption set up on this device. */
  hasKeys?: boolean;
}

type ItemAccess = AccessData<object, { max_role: Role; set_role_to: Role[] }>;

export function EncryptedShareModal({
  itemTitle,
  members,
  pending = [],
  searchResults = [],
  canManage = true,
  hasKeys = true,
}: EncryptedShareModalProps) {
  const t = usePatternTranslate();
  const [query, setQuery] = useState('');
  const [withoutEncryption, setWithoutEncryption] = useState<UserData<object>[]>([]);
  const [inviteNeedsKeys, setInviteNeedsKeys] = useState(false);
  const labels: Record<Role, string> = {
    reader: t('roleReader'),
    editor: t('roleEditor'),
    administrator: t('roleAdministrator'),
    owner: t('roleOwner'),
  };
  const subtexts: Record<Role, string> = {
    reader: t('subtextReader'),
    editor: t('subtextEditor'),
    administrator: t('subtextAdministrator'),
    owner: t('subtextOwner'),
  };

  const accesses: ItemAccess[] = members.map((member) => ({
    id: `access-${member.user.id}`,
    role: member.role,
    max_role: member.role,
    user: member.user,
    is_explicit: true,
    can_delete: member.user.id !== me.id,
    set_role_to: member.user.id === me.id ? [] : ROLES,
  }));

  // Inviting shares the item's key from this device, which needs encryption here.
  // Then someone without keys, or invited by an email with no account, joins as a
  // pending member: the item's key cannot be wrapped for them until they enable
  // encryption. Said before inviting, since the search could not say it.
  const onInviteUser = (users: UserData<object>[]) => {
    if (!hasKeys) {
      setInviteNeedsKeys(true);

      return;
    }

    const ready = new Set(searchResults.filter((result) => result.hasKeys).map((result) => result.user.id));
    const lacking = users.filter((user) => !ready.has(user.id));

    if (lacking.length > 0) setWithoutEncryption(lacking);
  };

  return (
    <>
      <ShareModal<object, object, { max_role: Role; set_role_to: Role[] }>
        isOpen
        onClose={() => undefined}
        modalTitle={t('shareTitle', { name: itemTitle })}
        canUpdate={canManage}
        canView
        accesses={accesses}
        invitationRoles={ROLES.map((role) => ({ label: labels[role], value: role }))}
        searchUsersResult={query ? searchResults.map((result) => result.user) : undefined}
        onSearchUsers={setQuery}
        onInviteUser={onInviteUser}
        onUpdateAccess={() => undefined}
        onDeleteAccess={() => undefined}
        onUpdateInvitation={() => undefined}
        onDeleteInvitation={() => undefined}
        accessRoleKey="max_role"
        getAccessRoles={(access) =>
          ROLES.map((role) => ({
            value: role,
            label: labels[role],
            subText: subtexts[role],
            isDisabled: !access.set_role_to.includes(role) && access.role !== role,
          }))
        }
        linkSettings={false}
        outsideSearchContent={
          <>
            {!hasKeys && (
              <div className="c__share-modal__link-settings pp-notice" data-testid="no-keys-notice">
                <div className="pp-pending__heading">
                  <p className="c__share-modal__link-settings__title pp-pending__title">{t('noKeysTitle')}</p>
                  <p className="pp-pending__hint">{t(canManage ? 'noKeysManager' : 'noKeysMember')}</p>
                </div>
                <Button size="small">{t('enableEncryption')}</Button>
              </div>
            )}
            {/* Accepting wraps the item's key for them, which needs encryption here. */}
            <PendingEncryptionSection rows={pending} canAccept={canManage && hasKeys} />
            <ShareModalCopyLinkFooter onCopyLink={() => undefined} onOk={() => undefined} />
          </>
        }
      >
        {!canManage && <HorizontalSeparator />}
      </ShareModal>
      <ConfirmationModal
        isOpen={withoutEncryption.length > 0}
        onClose={() => setWithoutEncryption([])}
        onDecide={() => setWithoutEncryption([])}
        title={t('inviteWithoutEncryptionTitle')}
      >
        <p>{t(withoutEncryption.length === 1 ? 'inviteWithoutEncryptionOne' : 'inviteWithoutEncryptionOther')}</p>
        {/* Each person as the modal shows its members: avatar, name, email. */}
        <ul className="pp-invite-list">
          {withoutEncryption.map((user) => (
            <li key={user.id}>
              <UserRow fullName={user.full_name} email={user.email} />
            </li>
          ))}
        </ul>
      </ConfirmationModal>
      <Modal
        isOpen={inviteNeedsKeys}
        onClose={() => setInviteNeedsKeys(false)}
        size={ModalSize.SMALL}
        title={t('inviteNeedsKeysTitle')}
        rightActions={
          <>
            <Button variant="bordered" color="neutral" onClick={() => setInviteNeedsKeys(false)}>
              {t('cancel')}
            </Button>
            <Button onClick={() => setInviteNeedsKeys(false)}>{t('enableEncryption')}</Button>
          </>
        }
      >
        <p>{t('inviteNeedsKeysText')}</p>
      </Modal>
    </>
  );
}
