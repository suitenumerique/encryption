import type { Meta, StoryContext, StoryObj } from '@storybook/react';
import { expect, userEvent, within } from 'storybook/test';

import { generateMetaDefault } from '@encryption/.storybook/helpers';
import { EncryptedShareModal, type EncryptedShareModalProps } from '@encryption/src/product-patterns/EncryptedShareModal';
import { PatternProvider } from '@encryption/src/product-patterns/PatternProvider';
import { me, pendingNowReady, pendingStillWaiting, withKeys, withoutKeys } from '@encryption/src/product-patterns/fixtures';
import { type PatternTranslate, createTranslate, toPatternLocale } from '@encryption/src/product-patterns/strings';

// The share modal of an encrypted item, as a product builds it on the design
// system's ShareModal: what encryption adds to it, one state per story, named
// after who looks at it ("As owner": someone who manages members; "As editor":
// someone who does not) and their situation.

export default {
  title: 'Product patterns/Share modal',
  ...generateMetaDefault({}),
} as Meta;

type Story = StoryObj;

type Scope = ReturnType<typeof within>;

const ITEM = 'Budget 2026';

// Someone invited by an email that has no account yet.
const NEWCOMER_EMAIL = 'nadia.roux@example.org';

async function findButtonByText(scope: Scope, text: string): Promise<HTMLButtonElement> {
  const label = await scope.findByText(text);
  const button = label.closest('button');

  await expect(button).not.toBeNull();

  return button as HTMLButtonElement;
}

async function search(body: Scope, text: string) {
  const input = (await body.findByTestId('share-search-field')).querySelector('input') as HTMLInputElement;

  await userEvent.clear(input);
  await userEvent.type(input, text);
}

// Picking someone clears the search, so each pick searches again.
async function pickAndInvite(body: Scope, document: Document, names: string[]) {
  for (const name of names) {
    await search(body, 'example');
    await userEvent.click(await body.findByText(name));
  }
  await userEvent.click(document.querySelector('.c__share-modal__search-field__actions button') as HTMLButtonElement);
}

// The design system's modal takes its title as no accessible name: found by it.
async function findModal(body: Scope, title: string): Promise<Scope> {
  return within((await body.findByText(title)).closest('.c__modal') as HTMLElement);
}

function story(
  props: Omit<EncryptedShareModalProps, 'itemTitle'>,
  check: (body: Scope, t: PatternTranslate, document: Document) => Promise<void>,
  description: string
): Story {
  return {
    parameters: { docs: { description: { story: description } } },
    render: (_args, context: Pick<StoryContext, 'globals'>) => (
      <PatternProvider locale={toPatternLocale(context.globals.locale)}>
        <EncryptedShareModal itemTitle={ITEM} {...props} />
      </PatternProvider>
    ),
    // The modal is portaled to the page body, and so are its menus.
    play: async ({ canvasElement, globals }) =>
      check(within(canvasElement.ownerDocument.body), createTranslate(toPatternLocale(globals.locale)), canvasElement.ownerDocument),
  };
}

const PENDING = [
  { user: pendingNowReady, hasPublicKey: true },
  { user: pendingStillWaiting, hasPublicKey: false },
];

const SEARCH = [
  { user: withKeys, hasKeys: true },
  { user: withoutKeys, hasKeys: false },
];

// ---------------------------------------------------------------------------
// As owner: someone who manages members.
// ---------------------------------------------------------------------------

export const AsOwner = story(
  {
    members: [
      { user: me, role: 'owner' },
      { user: withKeys, role: 'editor' },
    ],
  },
  async (body, t, document) => {
    await expect(await body.findByText(t('shareTitle', { name: ITEM }))).toBeInTheDocument();
    await expect(await body.findByText(withKeys.full_name)).toBeInTheDocument();
    // No link settings: the item stays restricted to its members.
    await expect(document.querySelector('.c__share-modal__link-settings')).toBeNull();
    await expect(body.queryByTestId('pending-encryption')).toBeNull();
  },
  'The members of an encrypted item. No link settings: the item stays restricted, so its members are the only way in.'
);

export const AsOwnerInvitingSomeoneWithoutEncryption = story(
  { members: [{ user: me, role: 'owner' }], searchResults: SEARCH },
  async (body, t, document) => {
    await pickAndInvite(body, document, [withoutKeys.full_name]);

    const modal = await findModal(body, t('inviteWithoutEncryptionTitle'));

    await expect(modal.getByText(t('inviteWithoutEncryptionOne'))).toBeInTheDocument();
    await expect(modal.getByText(withoutKeys.full_name)).toBeInTheDocument();
  },
  'Inviting someone who has not enabled encryption: the modal cannot mark them in its search results, so it asks before inviting. They join as pending members, and get access once they enable encryption.'
);

export const AsOwnerInvitingSeveralPeople = story(
  { members: [{ user: me, role: 'owner' }], searchResults: SEARCH },
  async (body, t, document) => {
    // An email with no account, then someone without encryption and someone with it.
    await search(body, NEWCOMER_EMAIL);
    await userEvent.click(await body.findByText(NEWCOMER_EMAIL));
    await pickAndInvite(body, document, [withoutKeys.full_name, withKeys.full_name]);

    const modal = await findModal(body, t('inviteWithoutEncryptionTitle'));

    await expect(modal.getByText(t('inviteWithoutEncryptionOther'))).toBeInTheDocument();
    await expect(modal.getAllByText(NEWCOMER_EMAIL).length).toBeGreaterThan(0);
    await expect(modal.getByText(withoutKeys.full_name)).toBeInTheDocument();
    // The one with encryption gets access at once: not listed.
    await expect(modal.queryByText(withKeys.full_name)).toBeNull();
  },
  'Inviting several people at once: the dialog lists only those who will be pending, someone without encryption and an email with no account. The one with encryption gets access at once.'
);

export const AsOwnerWithPendingMembers = story(
  {
    members: [
      { user: me, role: 'owner' },
      { user: pendingNowReady, role: 'editor' },
      { user: pendingStillWaiting, role: 'reader' },
    ],
    pending: PENDING,
  },
  async (body, t) => {
    const section = within(await body.findByTestId('pending-encryption'));

    await expect(section.getByText(t('pendingTitle'))).toBeInTheDocument();
    await expect(section.getByText(t('pendingWaitingHint'))).toBeInTheDocument();
    await expect(await findButtonByText(section, t('pendingAccept'))).toBeEnabled();
    await expect(section.getByTitle(t('pendingWaitingChipHint'))).toBeInTheDocument();
  },
  'Pending members: Accept for the one who has enabled encryption since, "Waiting for encryption" for the one who has not.'
);

export const AsOwnerAccepting = story(
  {
    members: [
      { user: me, role: 'owner' },
      { user: pendingNowReady, role: 'editor' },
    ],
    pending: [{ user: pendingNowReady, hasPublicKey: true, accepting: true }],
  },
  async (body, t) => {
    const section = within(await body.findByTestId('pending-encryption'));

    await expect(await findButtonByText(section, t('pendingAccepting'))).toBeDisabled();
  },
  "An Accept in progress: the item's key is being wrapped for the member."
);

export const AsOwnerWithoutEncryptionOnThisDevice = story(
  {
    hasKeys: false,
    members: [
      { user: me, role: 'owner' },
      { user: pendingNowReady, role: 'editor' },
      { user: pendingStillWaiting, role: 'reader' },
    ],
    pending: PENDING,
  },
  async (body, t) => {
    const notice = within(await body.findByTestId('no-keys-notice'));

    await expect(notice.getByText(t('noKeysTitle'))).toBeInTheDocument();
    await expect(notice.getByText(t('noKeysManager'))).toBeInTheDocument();
    await expect(await findButtonByText(notice, t('enableEncryption'))).toBeEnabled();

    // Accepting needs the item's key, which this device cannot open.
    const section = within(await body.findByTestId('pending-encryption'));

    await expect(section.queryByText(t('pendingAccept'))).toBeNull();
    await expect(section.getByText(t('pendingWaitingAcceptanceChip'))).toBeInTheDocument();
  },
  "An owner on a device without encryption (a new computer): the members and their roles still show, but accepting someone needs the item's key, which this device cannot open, so Accept is gone and a notice offers to enable encryption here."
);

export const AsOwnerInvitingWithoutEncryptionOnThisDevice = story(
  { hasKeys: false, members: [{ user: me, role: 'owner' }], searchResults: SEARCH },
  async (body, t, document) => {
    await pickAndInvite(body, document, [withKeys.full_name]);

    const modal = await findModal(body, t('inviteNeedsKeysTitle'));

    await expect(modal.getByText(t('inviteNeedsKeysText'))).toBeInTheDocument();
    await expect(await findButtonByText(modal, t('enableEncryption'))).toBeEnabled();
  },
  "The same owner inviting someone: sharing the item's key needs encryption on this device, so the modal offers to enable it instead."
);

// ---------------------------------------------------------------------------
// As editor: someone who does not manage members.
// ---------------------------------------------------------------------------

export const AsEditor = story(
  {
    canManage: false,
    members: [
      { user: me, role: 'editor' },
      { user: withKeys, role: 'owner' },
    ],
  },
  async (body, _t, document) => {
    await expect(await body.findByText(withKeys.full_name)).toBeInTheDocument();
    // Nothing to do: no search to invite with, no role to change.
    await expect(body.queryByTestId('share-search-field')).toBeNull();
    await expect(document.querySelector('[data-testid="access-role-dropdown-button"]')).toBeNull();
    await expect(body.queryByTestId('pending-encryption')).toBeNull();
  },
  'The members and their roles to read: no search to invite with, no role to change.'
);

export const AsEditorWithPendingMembers = story(
  {
    canManage: false,
    members: [
      { user: me, role: 'editor' },
      { user: withKeys, role: 'owner' },
      { user: pendingNowReady, role: 'editor' },
      { user: pendingStillWaiting, role: 'reader' },
    ],
    pending: PENDING,
  },
  async (body, t) => {
    const section = within(await body.findByTestId('pending-encryption'));

    await expect(section.getByText(t('pendingWaitingTitle'))).toBeInTheDocument();
    await expect(section.queryByText(t('pendingTitle'))).toBeNull();
    await expect(section.queryByText(t('pendingAccept'))).toBeNull();
    await expect(section.getByTitle(t('pendingWaitingAcceptanceChipHint'))).toHaveTextContent(t('pendingWaitingAcceptanceChip'));
    await expect(section.getByTitle(t('pendingWaitingChipHint'))).toHaveTextContent(t('pendingWaitingChip'));
  },
  'Pending members, nothing to do: "Waiting for access" and no Accept. Each person shows what they wait for: "Waiting for acceptance" for the one who has enabled encryption (an owner accepts them when they next open the item), "Waiting for encryption" for the other.'
);

export const AsEditorWaitingForAcceptance = story(
  {
    canManage: false,
    members: [
      { user: me, role: 'editor' },
      { user: withKeys, role: 'owner' },
    ],
    pending: [{ user: me, hasPublicKey: true }],
  },
  async (body, t) => {
    const section = within(await body.findByTestId('pending-encryption'));

    await expect(section.getByText(t('you', { name: me.full_name }))).toBeInTheDocument();
    await expect(section.getByText(t('pendingWaitingAcceptanceChip'))).toBeInTheDocument();
    await expect(body.queryByTestId('no-keys-notice')).toBeNull();
  },
  'An editor who is pending themselves: they have enabled encryption, and wait for an owner to accept them before they can open the item.'
);

export const AsEditorWithoutEncryptionYet = story(
  {
    canManage: false,
    hasKeys: false,
    members: [
      { user: me, role: 'editor' },
      { user: withKeys, role: 'owner' },
    ],
    pending: [{ user: me, hasPublicKey: false }],
  },
  async (body, t) => {
    const notice = within(await body.findByTestId('no-keys-notice'));

    await expect(notice.getByText(t('noKeysMember'))).toBeInTheDocument();
    await expect(await findButtonByText(notice, t('enableEncryption'))).toBeEnabled();

    const section = within(await body.findByTestId('pending-encryption'));

    await expect(section.getByText(t('you', { name: me.full_name }))).toBeInTheDocument();
    await expect(section.getByText(t('pendingWaitingChip'))).toBeInTheDocument();
  },
  'An editor added before they had encryption: they wait for their own encryption first, so the modal offers to enable it here; an owner then accepts them.'
);
