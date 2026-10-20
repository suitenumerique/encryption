import type { ReactNode } from 'react';
import { expect, userEvent, within } from 'storybook/test';

import { DocsEncryptDocModal } from '@encryption/src/product-patterns/docs/DocsEncryptDocModal';
import { DocsShareDialog } from '@encryption/src/product-patterns/docs/DocsShareDialog';
import { DriveShareModal } from '@encryption/src/product-patterns/drive/DriveShareModal';
import {
  invitedEmail,
  me,
  pendingNowReady,
  pendingStillWaiting,
  pendingWrapFailed,
  withKeys,
  withoutKeys,
} from '@encryption/src/product-patterns/fixtures';
import type { PatternTranslate } from '@encryption/src/product-patterns/strings';

export type PatternScope = ReturnType<typeof within>;

export interface PatternState {
  /** The story export name. */
  id: string;
  /** The story name in the sidebar. */
  name: string;
  /** The product file the state comes from, relative to the product's frontend app. */
  source: string;
  /** What the designer looks at, shown in the docs tab. */
  description: string;
  render: () => ReactNode;
  /** Asserts the element that sets the state apart, within the state's own container. */
  check: (scope: PatternScope, t: PatternTranslate) => Promise<void>;
  /** Drives the state further in its own story (menus open in a popover on the page body). */
  interact?: (body: PatternScope, t: PatternTranslate) => Promise<void>;
}

const DOCS = 'docs: src/frontend/apps/impress/src/features/docs';
const DRIVE = 'drive: src/frontend/apps/drive/src/features';
const DRIVE_ITEM = 'Budget 2026';

async function findButtonByText(scope: PatternScope, text: string): Promise<HTMLButtonElement> {
  const label = await scope.findByText(text);
  const button = label.closest('button');

  await expect(button).not.toBeNull();

  return button as HTMLButtonElement;
}

export const states: PatternState[] = [
  {
    id: 'DocsPlainDocument',
    name: 'Docs: plain document (reference)',
    source: `${DOCS}/doc-share/components/DocShareModal.tsx`,
    description:
      'The share dialog of a document that is not encrypted, as the reference: members, pending invitations, and the link settings in the footer, which an encrypted document does not have.',
    render: () => (
      <DocsShareDialog
        encrypted={false}
        members={[
          { user: me, role: 'owner' },
          { user: withKeys, role: 'editor' },
          { user: withoutKeys, role: 'reader' },
        ]}
        invitations={[{ email: invitedEmail, role: 'editor' }]}
      />
    ),
    check: async (scope, t) => {
      await expect(await scope.findByText(t('docsLinkSettings'))).toBeInTheDocument();
      await expect(scope.queryByLabelText(t('docsVerifyIdentityOf', { name: withKeys.full_name }))).toBeNull();
    },
  },
  {
    id: 'DocsEncryptedDocument',
    name: 'Docs: encrypted document, members',
    source: `${DOCS}/doc-share/components/DocShareMember.tsx`,
    description:
      'An encrypted document: the link settings are gone (DocShareModalFooter.tsx, the link must stay private), and every other member\'s avatar becomes a button that opens their encryption identity through the SDK (`openRecipientProfile`): fingerprint and trust decision. Trust itself (unknown, verified, changed, refused) is not shown in the dialog: it is the SDK overlay, see "Preview/Pages/RecipientProfile".',
    render: () => (
      <DocsShareDialog
        encrypted
        members={[
          { user: me, role: 'owner' },
          { user: withKeys, role: 'editor' },
        ]}
      />
    ),
    check: async (scope, t) => {
      await expect(await scope.findByLabelText(t('docsVerifyIdentityOf', { name: withKeys.full_name }))).toBeInTheDocument();
      await expect(scope.queryByLabelText(t('docsVerifyIdentityOf', { name: me.full_name }))).toBeNull();
      await expect(scope.queryByText(t('docsLinkSettings'))).toBeNull();
    },
  },
  {
    id: 'DocsSearchPlainDocument',
    name: 'Docs: search on a plain document (reference)',
    source: `${DOCS}/doc-share/components/DocShareModal.tsx`,
    description: 'Search results on a document that is not encrypted, as the reference: nobody is marked.',
    render: () => (
      <DocsShareDialog
        encrypted={false}
        members={[{ user: me, role: 'owner' }]}
        search={{
          query: 'example',
          results: [
            { user: withKeys, hasKeys: true },
            { user: withoutKeys, hasKeys: false },
          ],
        }}
      />
    ),
    check: async (scope, t) => {
      await expect(await scope.findByText(withoutKeys.full_name)).toBeInTheDocument();
      await expect(scope.queryByText(t('docsNoEncryption'))).toBeNull();
    },
  },
  {
    id: 'DocsSearchEncryptedDocument',
    name: 'Docs: search, recipients with and without encryption',
    source: `${DOCS}/doc-share/components/DocShareModal.tsx (QuickSearchInviteInputSection), SearchUserRow.tsx`,
    description:
      'Search results on an encrypted document. A person the directory has no encryption key for gets "No encryption" next to their name, with the explanation on hover: they can still be added, as a pending member. A person with keys shows nothing; whether their key is trusted is decided by the vault when the key is wrapped (Invite), which opens the SDK verification overlay ("Preview/Modals/VerifyRecipients") for an unknown, changed or refused key.',
    render: () => (
      <DocsShareDialog
        encrypted
        members={[{ user: me, role: 'owner' }]}
        search={{
          query: 'example',
          results: [
            { user: withKeys, hasKeys: true },
            { user: withoutKeys, hasKeys: false },
          ],
        }}
      />
    ),
    check: async (scope, t) => {
      await expect(await scope.findByText(t('docsChooseUser'))).toBeInTheDocument();
      await expect(await scope.findByLabelText(`${t('docsNoEncryption')}. ${t('docsNoEncryptionHint')}`)).toBeInTheDocument();
      await expect(scope.getAllByText(t('docsNoEncryption'))).toHaveLength(1);
    },
  },
  {
    id: 'DocsInviteByEmail',
    name: 'Docs: invite by email, no account',
    source: `${DOCS}/doc-share/components/DocShareModal.tsx (showEncryptedInviteHint)`,
    description:
      'Typing the email of someone with no account on an encrypted document: the email can be invited, and a line under the results says they get access only once they have signed up and enabled encryption. The invitation becomes a pending member at sign-up (DocShareAddMemberList.tsx).',
    render: () => <DocsShareDialog encrypted members={[{ user: me, role: 'owner' }]} search={{ query: invitedEmail, results: [] }} />,
    check: async (scope, t) => {
      await expect(await scope.findByText(t('docsChooseEmail'))).toBeInTheDocument();
      await expect(await scope.findByText(invitedEmail)).toBeInTheDocument();
      await expect(await scope.findByText(t('docsEncryptedInviteHint'))).toBeInTheDocument();
    },
  },
  {
    id: 'DocsInviteSelection',
    name: 'Docs: invite selection on an encrypted document',
    source: `${DOCS}/doc-share/components/DocShareAddMemberList.tsx`,
    description:
      'People picked for invitation, about to be invited. Nothing distinguishes them here: on Invite the document key is wrapped for those with keys (the vault may first open its verification overlay), and the others are created as pending members.',
    render: () => (
      <DocsShareDialog encrypted members={[{ user: me, role: 'owner' }]} selected={[withKeys, withoutKeys]} search={{ query: '', results: [] }} />
    ),
    check: async (scope, t) => {
      await expect(await findButtonByText(scope, t('docsInvite'))).toBeEnabled();
      await expect(await scope.findByText(withoutKeys.full_name)).toBeInTheDocument();
      await expect(scope.queryByText(t('docsCopyLink'))).toBeNull();
    },
  },
  {
    id: 'DocsPendingEncryption',
    name: 'Docs: pending members, action needed',
    source: `${DOCS}/doc-share/components/PendingEncryptionSection.tsx, hooks/useAutoAcceptPendingMembers.tsx`,
    description:
      'Members added before they had encryption, seen by a member manager. Above the list, "Action needed": one has enabled encryption since and can be accepted (Accept wraps the key for them, api/useAcceptEncryptionAccess.tsx); one has not, so a "Waiting for encryption" chip and one explanation line. The member list itself says nothing about them, as in Drive. When a manager opens the document, useAutoAcceptPendingMembers accepts the ready ones by itself, so this list is mostly seen for those still waiting.',
    render: () => (
      <DocsShareDialog
        encrypted
        members={[
          { user: me, role: 'owner' },
          { user: withKeys, role: 'editor' },
          { user: pendingNowReady, role: 'editor' },
          { user: pendingStillWaiting, role: 'reader' },
        ]}
        pending={[
          { user: pendingNowReady, hasPublicKey: true },
          { user: pendingStillWaiting, hasPublicKey: false },
        ]}
      />
    ),
    check: async (scope, t) => {
      const section = within(await scope.findByTestId('docs-pending-encryption'));

      await expect(section.getByText(t('docsActionNeeded'))).toBeInTheDocument();
      await expect(section.getByText(t('docsWaitingHint'))).toBeInTheDocument();
      await expect(await findButtonByText(section, t('docsAccept'))).toBeEnabled();
      await expect(section.getByTitle(t('docsWaitingChipTitle'))).toBeInTheDocument();
      await expect(section.queryByText(t('docsEncryptionEnabled'))).toBeNull();
      // Only the chip says it: no label next to the names in the member list.
      await expect(scope.getAllByText(t('docsWaitingForEncryption'))).toHaveLength(1);
    },
  },
  {
    id: 'DocsPendingReadOnly',
    name: 'Docs: pending members, viewer who cannot accept',
    source: `${DOCS}/doc-share/components/PendingEncryptionSection.tsx (canAccept), DocShareModal.tsx`,
    description:
      'The same list for a viewer who can see the members but not manage them: no search field, read-only roles, no Accept. The member who is ready shows "Encryption enabled", the other the "Waiting for encryption" chip. Same as Drive.',
    render: () => (
      <DocsShareDialog
        encrypted
        canManage={false}
        members={[
          { user: withKeys, role: 'owner' },
          { user: me, role: 'reader' },
          { user: pendingNowReady, role: 'editor' },
          { user: pendingStillWaiting, role: 'reader' },
        ]}
        pending={[
          { user: pendingNowReady, hasPublicKey: true },
          { user: pendingStillWaiting, hasPublicKey: false },
        ]}
      />
    ),
    check: async (scope, t) => {
      const section = within(await scope.findByTestId('docs-pending-encryption'));

      await expect(section.getByText(t('docsEncryptionEnabled'))).toBeInTheDocument();
      await expect(section.getByTitle(t('docsWaitingChipTitle'))).toBeInTheDocument();
      await expect(section.queryByText(t('docsAccept'))).toBeNull();
      await expect(scope.queryByPlaceholderText(t('docsSearchPlaceholder'))).toBeNull();
    },
  },
  {
    id: 'DocsPendingAcceptProgress',
    name: 'Docs: pending members, accepting and failures',
    source: `${DOCS}/doc-share/components/PendingEncryptionSection.tsx`,
    description:
      'The same section while Accept runs ("Accepting…", disabled) and after it failed: the member turned out not to have finished their encryption setup (back to waiting, with the error under the name), or the key could not be wrapped.',
    render: () => (
      <DocsShareDialog
        encrypted
        members={[
          { user: me, role: 'owner' },
          { user: pendingNowReady, role: 'editor' },
          { user: pendingStillWaiting, role: 'reader' },
          { user: pendingWrapFailed, role: 'reader' },
        ]}
        pending={[
          { user: pendingNowReady, hasPublicKey: true, accepting: true },
          { user: pendingStillWaiting, hasPublicKey: false, error: 'not-onboarded' },
          { user: pendingWrapFailed, hasPublicKey: true, error: 'wrap-failed' },
        ]}
      />
    ),
    check: async (scope, t) => {
      const section = within(await scope.findByTestId('docs-pending-encryption'));

      await expect(await findButtonByText(section, t('docsAccepting'))).toBeDisabled();
      await expect(section.getByText(t('docsNotOnboardedError'))).toBeInTheDocument();
      await expect(section.getByText(t('docsWrapFailedError'))).toBeInTheDocument();
    },
  },
  {
    id: 'DocsNoAccessNeedsSetup',
    name: 'Docs: viewer without encryption',
    source: `${DOCS}/doc-share/components/DocShareModal.tsx, doc-management/hooks/useEncryptionAccessCopy.tsx`,
    description:
      'The viewer has not enabled encryption and opens the share dialog of an encrypted document: the dialog shows only this state instead of members and search, with "Enable encryption" (ButtonEnableEncryption), which opens the encryption onboarding.',
    render: () => <DocsShareDialog encrypted accessError="needs-setup" />,
    check: async (scope, t) => {
      await expect(await scope.findByText(t('docsEncryptedDocument'))).toBeInTheDocument();
      await expect(scope.getByText(t('docsNeedsSetup'))).toBeInTheDocument();
      await expect(await findButtonByText(scope, t('docsEnableEncryption'))).toBeEnabled();
      await expect(scope.queryByText(t('docsSearchPlaceholder'))).toBeNull();
    },
  },
  {
    id: 'DocsNoAccessNoKey',
    name: 'Docs: viewer with encryption but no key on the document',
    source: `${DOCS}/doc-management/hooks/useEncryptionAccessCopy.tsx`,
    description: 'The viewer has encryption, but the document holds no key for them (for example the key could not be opened).',
    render: () => <DocsShareDialog encrypted accessError="no-key" />,
    check: async (scope, t) => {
      await expect(await scope.findByText(t('docsEncryptedDocument'))).toBeInTheDocument();
      await expect(scope.getByText(t('docsNoKeyForYou'))).toBeInTheDocument();
      await expect(scope.queryByText(t('docsEnableEncryption'))).toBeNull();
    },
  },
  {
    id: 'DocsWaitingForAccessNeedsSetup',
    name: 'Docs: viewer pending, encryption not enabled',
    source: `${DOCS}/doc-management/hooks/useEncryptionAccessCopy.tsx`,
    description:
      'The viewer is a pending member (`is_pending_encryption_for_user`) and has still not enabled encryption: they are asked to ("Enable encryption" opens the onboarding), and will get access when the owner next opens the document.',
    render: () => <DocsShareDialog encrypted accessError="pending-needs-setup" />,
    check: async (scope, t) => {
      await expect(await scope.findByText(t('docsWaitingForAccess'))).toBeInTheDocument();
      await expect(scope.getByText(t('docsPendingNeedsSetup'))).toBeInTheDocument();
      await expect(await findButtonByText(scope, t('docsEnableEncryption'))).toBeEnabled();
    },
  },
  {
    id: 'DocsWaitingForAccess',
    name: 'Docs: viewer pending, encryption enabled',
    source: `${DOCS}/doc-management/hooks/useEncryptionAccessCopy.tsx`,
    description: 'The viewer is a pending member who has enabled encryption since: nothing left to do, they wait for the owner to open the document.',
    render: () => <DocsShareDialog encrypted accessError="pending" />,
    check: async (scope, t) => {
      await expect(await scope.findByText(t('docsWaitingForAccess'))).toBeInTheDocument();
      await expect(scope.getByText(t('docsPendingSetUp'))).toBeInTheDocument();
      await expect(scope.queryByText(t('docsEnableEncryption'))).toBeNull();
    },
  },
  {
    id: 'DocsEncryptBlocked',
    name: 'Docs: encrypt document, blocked',
    source: `${DOCS}/doc-management/components/ModalEncryptDoc.tsx`,
    description:
      'The entry to encryption ("Encrypt document" in the document menu, DocToolBox.tsx). It lists what blocks it in a red notice: the viewer has no encryption keys, and the link is not private (an encrypted document must stay restricted, which is why its share dialog has no link settings). Files still in antivirus analysis also block it. Without keys, the primary action is "Enable encryption" (ButtonEnableEncryption): the onboarding opens over the modal, which can encrypt once it is done.',
    render: () => <DocsEncryptDocModal hasKeys={false} linkReach="public" />,
    check: async (scope, t) => {
      await expect(await scope.findByText(t('docsBlockerNoKeys'))).toBeInTheDocument();
      await expect(scope.getByText(t('docsBlockerNotPrivate', { reach: t('docsReachLowerPublic') }))).toBeInTheDocument();
      await expect(await findButtonByText(scope, t('docsEnableEncryption'))).toBeEnabled();
      await expect(scope.queryByText(t('docsEncrypt'))).toBeNull();
    },
  },
  {
    id: 'DocsEncryptBlockedWithKeys',
    name: 'Docs: encrypt document, link not private',
    source: `${DOCS}/doc-management/components/ModalEncryptDoc.tsx`,
    description: 'The viewer has keys but the link is connected: "Encrypt" stays disabled until the document is private.',
    render: () => <DocsEncryptDocModal hasKeys linkReach="authenticated" />,
    check: async (scope, t) => {
      await expect(await scope.findByText(t('docsBlockerNotPrivate', { reach: t('docsReachLowerConnected') }))).toBeInTheDocument();
      await expect(await findButtonByText(scope, t('docsEncrypt'))).toBeDisabled();
    },
  },
  {
    id: 'DocsEncryptWithPendingCollaborators',
    name: 'Docs: encrypt document, collaborators without encryption',
    source: `${DOCS}/doc-management/components/ModalEncryptDoc.tsx`,
    description:
      'Encryption is possible, but some members (and every pending email invitation) have no encryption yet: they will become pending members, the "Action needed" section of the share dialog.',
    render: () => <DocsEncryptDocModal hasKeys linkReach="restricted" pendingCount={2} />,
    check: async (scope, t) => {
      await expect(await scope.findByText(t('docsPendingCollaboratorsOther', { count: 2 }))).toBeInTheDocument();
      await expect(await findButtonByText(scope, t('docsEncrypt'))).toBeEnabled();
    },
  },
  {
    id: 'DocsEncryptReady',
    name: 'Docs: encrypt document, ready',
    source: `${DOCS}/doc-management/components/ModalEncryptDoc.tsx`,
    description: 'Nothing blocks encryption and every member has encryption: no alert at all.',
    render: () => <DocsEncryptDocModal hasKeys linkReach="restricted" />,
    check: async (scope, t) => {
      await expect(await findButtonByText(scope, t('docsEncrypt'))).toBeEnabled();
      await expect(scope.queryByText(t('docsBlockerNoKeys'))).toBeNull();
    },
  },
  {
    id: 'DrivePlainItem',
    name: 'Drive: plain item (reference)',
    source: `${DRIVE}/explorer/components/modals/share/ItemShareModal.tsx`,
    description:
      "Drive's share modal of an item that is not encrypted, as the reference: the design system's ShareModal with link settings and the copy-link footer.",
    render: () => (
      <DriveShareModal
        itemTitle={DRIVE_ITEM}
        encrypted={false}
        members={[
          { user: me, role: 'owner' },
          { user: withKeys, role: 'editor' },
          { user: withoutKeys, role: 'reader' },
        ]}
        invitations={[{ email: invitedEmail, role: 'editor' }]}
      />
    ),
    check: async (scope, t) => {
      await expect(await scope.findByText(`${t('driveShareTitle')} ${DRIVE_ITEM}`)).toBeInTheDocument();
      await expect(await scope.findByText(t('driveReachRestricted'))).toBeInTheDocument();
      await expect(scope.queryByTestId('drive-pending-encryption')).toBeNull();
    },
  },
  {
    id: 'DriveEncryptedVerifyIdentity',
    name: 'Drive: encrypted item, verify identity',
    source: `${DRIVE}/explorer/components/modals/share/ItemShareModal.tsx (withIdentity)`,
    description:
      'An encrypted item. ShareModal draws the member rows itself, so Drive puts "Verify identity" at the top of each other member\'s role menu (the play opens Alice\'s): it opens their encryption identity through the SDK. No link settings: an encrypted item stays private, so its members are the only way in.',
    render: () => (
      <DriveShareModal
        itemTitle={DRIVE_ITEM}
        encrypted
        members={[
          { user: me, role: 'owner' },
          { user: withKeys, role: 'editor' },
        ]}
      />
    ),
    check: async (scope, t) => {
      await expect(await scope.findByText(withKeys.full_name)).toBeInTheDocument();
      await expect(scope.queryByTestId('drive-pending-encryption')).toBeNull();
      await expect(scope.queryByText(t('driveReachRestricted'))).toBeNull();
    },
    interact: async (body, t) => {
      const row = (await body.findByText(withKeys.full_name)).closest('.c__share-member-item');

      await expect(row).not.toBeNull();
      await userEvent.click(within(row as HTMLElement).getByTestId('access-role-dropdown-button'));
      await expect(await body.findByText(t('driveVerifyIdentity'))).toBeInTheDocument();
    },
  },
  {
    id: 'DrivePendingEncryption',
    name: 'Drive: pending members, action needed',
    source: `${DRIVE}/encryption/sharing/PendingEncryptionSection.tsx, useAutoAcceptPendingMembers.ts`,
    description:
      'Members added to the encrypted item before they had encryption, in `outsideSearchContent` above the copy-link footer: Accept for the one who has enabled encryption since, a "Waiting for encryption" chip for the other. The member list itself shows nothing for them (no slot for it). As in Docs, a manager opening the item accepts the ready ones automatically.',
    render: () => (
      <DriveShareModal
        itemTitle={DRIVE_ITEM}
        encrypted
        members={[
          { user: me, role: 'owner' },
          { user: pendingNowReady, role: 'editor' },
          { user: pendingStillWaiting, role: 'reader' },
        ]}
        pending={[
          { user: pendingNowReady, hasPublicKey: true },
          { user: pendingStillWaiting, hasPublicKey: false },
        ]}
      />
    ),
    check: async (scope, t) => {
      const section = within(await scope.findByTestId('drive-pending-encryption'));

      await expect(section.getByText(t('drivePendingTitle'))).toBeInTheDocument();
      await expect(section.getByText(t('drivePendingWaitingHint'))).toBeInTheDocument();
      await expect(await findButtonByText(section, t('drivePendingAccept'))).toBeEnabled();
      await expect(section.getByTitle(t('drivePendingWaitingChipHint'))).toBeInTheDocument();
    },
  },
  {
    id: 'DrivePendingViewerCannotAccept',
    name: 'Drive: pending members, viewer who cannot accept',
    source: `${DRIVE}/encryption/sharing/PendingEncryptionSection.tsx (canAccept)`,
    description:
      'The same list for a viewer who may not manage members: no Accept, "Encryption enabled" for the member who is ready, the chip for the other. Docs shows no such list to this viewer.',
    render: () => (
      <DriveShareModal
        itemTitle={DRIVE_ITEM}
        encrypted
        canManage={false}
        members={[
          { user: me, role: 'reader' },
          { user: withKeys, role: 'owner' },
          { user: pendingNowReady, role: 'editor' },
          { user: pendingStillWaiting, role: 'reader' },
        ]}
        pending={[
          { user: pendingNowReady, hasPublicKey: true },
          { user: pendingStillWaiting, hasPublicKey: false },
        ]}
      />
    ),
    check: async (scope, t) => {
      const section = within(await scope.findByTestId('drive-pending-encryption'));

      await expect(section.getByText(t('drivePendingEncryptionEnabled'))).toBeInTheDocument();
      await expect(section.queryByText(t('drivePendingAccept'))).toBeNull();
    },
  },
  {
    id: 'DrivePendingAcceptProgress',
    name: 'Drive: pending members, accepting and failure',
    source: `${DRIVE}/encryption/sharing/PendingEncryptionSection.tsx`,
    description:
      'Accept in flight ("Accepting…", disabled), and a member who turned out not to have finished their encryption setup: back to the chip, with the error under the name.',
    render: () => (
      <DriveShareModal
        itemTitle={DRIVE_ITEM}
        encrypted
        members={[
          { user: me, role: 'owner' },
          { user: pendingNowReady, role: 'editor' },
          { user: pendingStillWaiting, role: 'reader' },
        ]}
        pending={[
          { user: pendingNowReady, hasPublicKey: true, accepting: true },
          { user: pendingStillWaiting, hasPublicKey: false, error: true },
        ]}
      />
    ),
    check: async (scope, t) => {
      const section = within(await scope.findByTestId('drive-pending-encryption'));

      await expect(await findButtonByText(section, t('drivePendingAccepting'))).toBeDisabled();
      await expect(section.getByText(t('drivePendingNoPublicKey'))).toBeInTheDocument();
    },
  },
];
