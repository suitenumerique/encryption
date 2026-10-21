import { type AccessData, Button, HorizontalSeparator, ShareModal, ShareModalCopyLinkFooter } from '@gouvfr-lasuite/ui-components';
import { ShieldCheck } from '@gouvfr-lasuite/ui-components/icons';

import { usePatternTranslate } from '@encryption/src/product-patterns/PatternProvider';
import { DrivePendingEncryptionSection, type DrivePendingRow } from '@encryption/src/product-patterns/drive/DrivePendingEncryptionSection';
import { type PatternUser, me } from '@encryption/src/product-patterns/fixtures';

// Drive composes the design system's ShareModal itself
// (explorer/components/modals/share/ItemShareModal.tsx). Encryption only uses
// the slots the modal leaves: `outsideSearchContent` for the pending section,
// and the top of each member's role menu for "Verify identity", since the
// modal draws the rows itself.

type DriveRole = 'reader' | 'editor' | 'administrator' | 'owner';

export interface DriveMember {
  user: PatternUser;
  role: DriveRole;
}

export interface DriveShareModalProps {
  itemTitle: string;
  encrypted: boolean;
  members: DriveMember[];
  invitations?: { email: string; role: DriveRole }[];
  pending?: DrivePendingRow[];
  canManage?: boolean;
}

type DriveAccess = AccessData<object, { max_role: DriveRole; set_role_to: DriveRole[] }>;

export function DriveShareModal({ itemTitle, encrypted, members, invitations = [], pending = [], canManage = true }: DriveShareModalProps) {
  const t = usePatternTranslate();
  const roleLabels: Record<DriveRole, string> = {
    reader: t('driveRoleReader'),
    editor: t('driveRoleEditor'),
    administrator: t('driveRoleAdministrator'),
    owner: t('driveRoleOwner'),
  };
  const roleSubtexts: Record<DriveRole, string> = {
    reader: t('driveSubtextReader'),
    editor: t('driveSubtextEditor'),
    administrator: t('driveSubtextAdmin'),
    owner: t('driveSubtextOwner'),
  };
  const roles = (Object.keys(roleLabels) as DriveRole[]).map((role) => ({ label: roleLabels[role], value: role }));

  const accesses: DriveAccess[] = members.map((member) => ({
    id: `access-${member.user.id}`,
    role: member.role,
    max_role: member.role,
    user: member.user,
    is_explicit: true,
    can_delete: member.user.id !== me.id,
    set_role_to: member.user.id === me.id ? [] : (Object.keys(roleLabels) as DriveRole[]),
  }));
  const ownerCount = accesses.filter((access) => access.max_role === 'owner').length;

  // `withIdentity` in ItemShareModal.tsx: on an encrypted item, the top of a
  // member's role menu opens their encryption identity. Not for oneself.
  const accessRoleTopMessage = (access: DriveAccess) => {
    const isLastOwner = ownerCount === 1 && access.set_role_to.length === 0 && access.role === 'owner';
    const message = isLastOwner && access.user.id === me.id ? t('driveOnlyOwner') : undefined;

    if (!encrypted || access.user.id === me.id) {
      return message;
    }

    return (
      <>
        {message}
        <div className="pp-drive-verify-identity">
          <Button size="small" variant="tertiary" icon={<ShieldCheck aria-hidden size={16} />}>
            {t('driveVerifyIdentity')}
          </Button>
        </div>
      </>
    );
  };

  return (
    <ShareModal<object, object, { max_role: DriveRole; set_role_to: DriveRole[] }>
      isOpen
      onClose={() => undefined}
      modalTitle={`${t('driveShareTitle')} ${itemTitle}`}
      canUpdate={canManage}
      canView
      accesses={accesses}
      invitations={invitations.map((invitation) => ({
        id: `invitation-${invitation.email}`,
        role: invitation.role,
        email: invitation.email,
        user: { id: invitation.email, full_name: invitation.email, email: invitation.email },
      }))}
      invitationRoles={roles}
      onSearchUsers={() => undefined}
      onInviteUser={() => undefined}
      onUpdateAccess={() => undefined}
      onDeleteAccess={() => undefined}
      onUpdateInvitation={() => undefined}
      onDeleteInvitation={() => undefined}
      accessRoleKey="max_role"
      accessRoleTopMessage={accessRoleTopMessage}
      getAccessRoles={(access) =>
        (Object.keys(roleLabels) as DriveRole[]).map((role) => ({
          value: role,
          label: roleLabels[role],
          subText: roleSubtexts[role],
          isDisabled: !access.set_role_to.includes(role) && access.role !== role,
        }))
      }
      // An encrypted item stays restricted: its members are the only way in.
      linkSettings={!encrypted}
      showLinkRole
      linkReach="restricted"
      linkReachChoices={[
        { value: 'restricted', label: t('driveReachRestricted'), isDisabled: false },
        { value: 'authenticated', label: t('driveReachAuthenticated'), isDisabled: false },
        { value: 'public', label: t('driveReachPublic'), isDisabled: false },
      ]}
      linkRoleChoices={[]}
      outsideSearchContent={
        <>
          {encrypted && <DrivePendingEncryptionSection rows={pending} canAccept={canManage} />}
          <ShareModalCopyLinkFooter onCopyLink={() => undefined} onOk={() => undefined} />
        </>
      }
    >
      {!canManage && <HorizontalSeparator />}
    </ShareModal>
  );
}
