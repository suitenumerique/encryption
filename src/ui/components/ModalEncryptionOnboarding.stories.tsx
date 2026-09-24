import { Meta, StoryFn } from '@storybook/react';
import { expect, userEvent, waitFor } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { handleGetApiEmergencyAccessTrusted, handleGetApiPublicKeys, handleGetApiPublicKeysNext } from '@encryption/src/ui/api/generated/msw.gen';
import { ModalEncryptionOnboarding } from '@encryption/src/ui/components/ModalEncryptionOnboarding';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { sampleEmergencyEscrowRecord, samplePublicKey } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof ModalEncryptionOnboarding;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Pages/EncryptionOnboarding',
  component: ModalEncryptionOnboarding,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: true,
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => {
  return <ModalEncryptionOnboarding {...args} />;
};

const NewUserStory = Template.bind({});
NewUserStory.args = {
  getToken: async () => 'mock-jwt-token',
  userId: '00000000-0000-0000-0000-000000000000',
  onClose: () => console.log('onClose'),
  onSuccess: (pk) => console.log('onSuccess', pk),
  onUseAnotherDevice: () => console.log('onUseAnotherDevice'),
  onOpenEmergencyAccess: () => console.log('onOpenEmergencyAccess'),
  hasExistingBackendKey: false,
};
NewUserStory.parameters = {
  msw: {
    handlers: [handleGetApiPublicKeys({ body: { keys: [] } }), handleGetApiPublicKeysNext({ body: { next_version: 1, next_generation: 1 } })],
  },
};
NewUserStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_enable'));
};

export const NewUser = prepareStory(NewUserStory);

const ExistingUserStory = Template.bind({});
ExistingUserStory.args = {
  getToken: async () => 'mock-jwt-token',
  userId: '00000000-0000-0000-0000-000000000000',
  onClose: () => console.log('onClose'),
  onSuccess: (pk) => console.log('onSuccess', pk),
  onUseAnotherDevice: () => console.log('onUseAnotherDevice'),
  onOpenEmergencyAccess: () => console.log('onOpenEmergencyAccess'),
  hasExistingBackendKey: true,
  existingKeyFingerprint: '0031712345678901234567890123456789012345',
  userInfo: { name: 'Alice Martin', email: 'alice.martin@numerique.gouv.fr' },
};
ExistingUserStory.parameters = {
  msw: {
    handlers: [
      handleGetApiPublicKeys(({ request }) => {
        const userIds = new URL(request.url).searchParams.getAll('user_ids');

        return Response.json({ keys: userIds.map((user_id) => ({ ...samplePublicKey, user_id })) });
      }),
    ],
  },
};
ExistingUserStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_existing'));
  await playFindButton(canvasElement, i18n.t('onboarding.btn_restore_from_backup'));
};

export const ExistingUser = prepareStory(ExistingUserStory);

// No ACTIVE key, but counters past 1: the account registered before and was reset.
const PreviousIdentityStory = Template.bind({});
PreviousIdentityStory.args = {
  ...NewUserStory.args,
};
const previousIdentityHandlers = [
  handleGetApiPublicKeys({ body: { keys: [] } }),
  handleGetApiPublicKeysNext({ body: { next_version: 3, next_generation: 2 } }),
];
PreviousIdentityStory.parameters = { msw: { handlers: previousIdentityHandlers } };
PreviousIdentityStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_previous_identity'));
  // The trusted-contacts request answers 501 here: no sentence about contacts.
  expect(canvasElement.textContent).not.toContain('@');
};

export const PreviousIdentity = prepareStory(PreviousIdentityStory);

// Same history, but the account had designated trusted contacts before the
// identity was disabled: the screen names them as a way back in. An invitation
// that was never accepted is not one, so the pending contact stays out.
const trustedContact = (email: string, status: 'confirmed' | 'invited') => ({
  id: '11111111-1111-1111-1111-111111111111',
  grantee_user_id: '22222222-2222-2222-2222-222222222222',
  grantee_email: email,
  status,
  wait_time_days: 15,
  created_at_millis: 1_700_000_000_000,
  recovery_requested_at_millis: null,
  deadline_millis: null,
  vault_active: false,
  escrow: sampleEmergencyEscrowRecord,
});

const PreviousIdentityWithContactsStory = Template.bind({});
PreviousIdentityWithContactsStory.args = { ...NewUserStory.args };
PreviousIdentityWithContactsStory.parameters = {
  msw: {
    handlers: [
      ...previousIdentityHandlers,
      handleGetApiEmergencyAccessTrusted({
        body: {
          contacts: [
            trustedContact('bob.dupont@numerique.gouv.fr', 'confirmed'),
            trustedContact('carol.bernard@numerique.gouv.fr', 'confirmed'),
            trustedContact('dan.martin@numerique.gouv.fr', 'invited'),
          ],
        },
      }),
    ],
  },
};
PreviousIdentityWithContactsStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_previous_identity'));
  await waitFor(() => expect(canvasElement.textContent).toContain('bob.dupont@numerique.gouv.fr'));
  expect(canvasElement.textContent).toContain('carol.bernard@numerique.gouv.fr');
  expect(canvasElement.textContent).not.toContain('dan.martin@numerique.gouv.fr');
};

export const PreviousIdentityWithContacts = prepareStory(PreviousIdentityWithContactsStory);

// Internal state, no prop to set it: the click is the only way in.
const RestoreStory = Template.bind({});
RestoreStory.args = { ...ExistingUserStory.args };
RestoreStory.parameters = ExistingUserStory.parameters;
RestoreStory.play = async ({ canvasElement }) => {
  const restore = await playFindButton(canvasElement, i18n.t('onboarding.btn_restore_from_backup'));

  await userEvent.click(restore);
  await playFindHeading(canvasElement, i18n.t('onboarding.title_restore'));
};

export const Restore = prepareStory(RestoreStory);

const LastResortStory = Template.bind({});
LastResortStory.args = { ...ExistingUserStory.args };
LastResortStory.parameters = ExistingUserStory.parameters;
LastResortStory.play = async ({ canvasElement }) => {
  const lastResort = await playFindButton(canvasElement, i18n.t('onboarding.btn_last_resort'));

  await userEvent.click(lastResort);
  await playFindHeading(canvasElement, i18n.t('onboarding.title_last_resort'));
};

export const LastResort = prepareStory(LastResortStory);

// The recovery phrase step: the keys are minted locally and the confirmation
// stays locked until the phrase left the screen one way or another.
const BackupStory = Template.bind({});
BackupStory.args = { ...NewUserStory.args };
BackupStory.parameters = NewUserStory.parameters;
BackupStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await playFindHeading(canvasElement, i18n.t('onboarding.title_backup'));

  // Hidden until asked for, and nothing to confirm before the phrase left the screen.
  expect(await playFindButton(canvasElement, i18n.t('onboarding.btn_backup_done'))).toBeDisabled();
  await playFindButton(canvasElement, i18n.t('onboarding.btn_reveal'));
  expect(canvasElement.querySelector(`.${styles.words}`)).toBeNull();
};

export const Backup = prepareStory(BackupStory);

// The product's cross on the backup step does not close: the screen holds a
// guard that asks first. The story ends with the prompt open, which is the
// state it shows; "go back" and "close anyway" are exercised by hand, since
// driving them here would open and close the prompt in front of the viewer.
const BackupCancelPromptStory = Template.bind({});
BackupCancelPromptStory.args = { ...NewUserStory.args };
BackupCancelPromptStory.parameters = NewUserStory.parameters;
BackupCancelPromptStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await playFindHeading(canvasElement, i18n.t('onboarding.title_backup'));
  await userEvent.click(await playFindButton(canvasElement, 'Close'));
  await playFindHeading(document.body, i18n.t('onboarding.cancel_setup_title'));
};

export const BackupCancelPrompt = prepareStory(BackupCancelPromptStory);
