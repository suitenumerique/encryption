import { Meta, StoryFn } from '@storybook/react';
import { expect, fn, userEvent, waitFor, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { API_ERROR_VAULT_NOT_FOUND } from '@encryption/src/shared/error-codes';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import {
  handleGetApiEmergencyAccessTrusted,
  handleGetApiPublicKeys,
  handleGetApiPublicKeysNext,
  handleGetApiVaultMeta,
  handlePostApiPublicKeysRegisterInit,
} from '@encryption/src/ui/api/generated/msw.gen';
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
  getIdToken: async () => 'mock-jwt-token',
  userId: '00000000-0000-0000-0000-000000000000',
  onClose: () => console.log('onClose'),
  onSuccess: (pk) => console.log('onSuccess', pk),
  onUseAnotherDevice: () => console.log('onUseAnotherDevice'),
  onOpenEmergencyAccess: () => console.log('onOpenEmergencyAccess'),
  onStepUp: () => console.log('onStepUp'),
  hasExistingBackendKey: false,
};
const newUserHandlers = [
  handleGetApiPublicKeys({ body: { keys: [] } }),
  handleGetApiPublicKeysNext({ body: { next_version: 1, next_generation: 1 } }),
  handleGetApiVaultMeta(() => Response.json({ code: API_ERROR_VAULT_NOT_FOUND }, { status: 404 })),
];
NewUserStory.parameters = {
  msw: { handlers: newUserHandlers },
};
NewUserStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_enable'));
};

export const NewUser = prepareStory(NewUserStory);

const ExistingUserStory = Template.bind({});
ExistingUserStory.args = {
  getIdToken: async () => 'mock-jwt-token',
  userId: '00000000-0000-0000-0000-000000000000',
  onClose: () => console.log('onClose'),
  onSuccess: (pk) => console.log('onSuccess', pk),
  onUseAnotherDevice: () => console.log('onUseAnotherDevice'),
  onOpenEmergencyAccess: () => console.log('onOpenEmergencyAccess'),
  onStepUp: () => console.log('onStepUp'),
  hasExistingBackendKey: true,
  existingKeyFingerprint: '1031712345678901234567890123456789012345',
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
  // Two ways back, as selectable cards: another device first, then the phrase.
  await within(canvasElement).findByRole('radio', { name: new RegExp(i18n.t('onboarding.btn_use_another_device')) });
  await within(canvasElement).findByRole('radio', { name: new RegExp(i18n.t('onboarding.btn_restore_from_backup')) });
  await playFindButton(canvasElement, i18n.t('onboarding.btn_continue'));
};

export const ExistingUser = prepareStory(ExistingUserStory);

// This browser held the vault but forgot it after a year without use: the same
// choice, explained.
const ExistingUserDeEnrolledStory = Template.bind({});
ExistingUserDeEnrolledStory.args = { ...ExistingUserStory.args };
ExistingUserDeEnrolledStory.parameters = {
  ...ExistingUserStory.parameters,
  encryption: {
    ...ExistingUserStory.parameters?.encryption,
    hasKeys: async () => ({ hasKeys: false, deEnrolled: { deEnrolledAt: 1_750_000_000_000, inactivityDays: 365 } }),
  },
};
ExistingUserDeEnrolledStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_existing'));
  await waitFor(() => expect(canvasElement.textContent).toContain(i18n.t('onboarding.de_enrolled_notice', { count: 365 })));
};

export const ExistingUserDeEnrolled = prepareStory(ExistingUserDeEnrolledStory);

// No ACTIVE key, but a dormant vault: the account registered before and was reset.
const PreviousIdentityStory = Template.bind({});
PreviousIdentityStory.args = {
  ...NewUserStory.args,
};
const previousIdentityHandlers = [
  handleGetApiPublicKeys({ body: { keys: [] } }),
  handleGetApiPublicKeysNext({ body: { next_version: 3, next_generation: 2 } }),
  handleGetApiVaultMeta({ body: { kdf_variants: [{ kdf_ops: 3, kdf_mem: 67108864 }] } }),
];
PreviousIdentityStory.parameters = { msw: { handlers: previousIdentityHandlers } };
PreviousIdentityStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_previous_identity'));
  // The trusted-contacts request answers 501 here: no sentence about contacts.
  expect(canvasElement.textContent).not.toContain('@');
};

export const PreviousIdentity = prepareStory(PreviousIdentityStory);

// The same history, seen from a browser that also forgot its vault after a year
// without use (the identity was reset from another device meanwhile): explained too.
const PreviousIdentityDeEnrolledStory = Template.bind({});
PreviousIdentityDeEnrolledStory.args = { ...PreviousIdentityStory.args };
PreviousIdentityDeEnrolledStory.parameters = {
  ...PreviousIdentityStory.parameters,
  encryption: {
    ...PreviousIdentityStory.parameters?.encryption,
    hasKeys: async () => ({ hasKeys: false, deEnrolled: { deEnrolledAt: 1_750_000_000_000, inactivityDays: 365 } }),
  },
};
PreviousIdentityDeEnrolledStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_previous_identity'));
  await waitFor(() => expect(canvasElement.textContent).toContain(i18n.t('onboarding.de_enrolled_notice', { count: 365 })));
};

export const PreviousIdentityDeEnrolled = prepareStory(PreviousIdentityDeEnrolledStory);

// Registered before, but every dormant vault was deleted by the retention job: no
// phrase can restore anything, so the fresh start is offered directly.
const PurgedHistoryStory = Template.bind({});
PurgedHistoryStory.args = { ...NewUserStory.args };
PurgedHistoryStory.parameters = {
  msw: {
    handlers: [
      handleGetApiPublicKeys({ body: { keys: [] } }),
      handleGetApiPublicKeysNext({ body: { next_version: 3, next_generation: 2 } }),
      handleGetApiVaultMeta(() => Response.json({ code: API_ERROR_VAULT_NOT_FOUND }, { status: 404 })),
    ],
  },
};
PurgedHistoryStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_enable'));
  expect(canvasElement.textContent).not.toContain(i18n.t('onboarding.title_previous_identity'));
};

export const PurgedHistory = prepareStory(PurgedHistoryStory);

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
  await userEvent.click(await within(canvasElement).findByRole('radio', { name: new RegExp(i18n.t('onboarding.btn_restore_from_backup')) }));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await playFindHeading(canvasElement, i18n.t('onboarding.title_restore'));
};

export const Restore = prepareStory(RestoreStory);

// 24 words of the English list, pasted at once like a saved sheet.
const PASTED_PHRASE = Array.from({ length: 24 }, () => 'abandon').join(' ');

async function playSubmitPhrase(canvasElement: HTMLElement) {
  await userEvent.click(await within(canvasElement).findByRole('radio', { name: new RegExp(i18n.t('onboarding.btn_restore_from_backup')) }));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await userEvent.click(await within(canvasElement).findByLabelText('word 1'));
  await userEvent.paste(PASTED_PHRASE);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_restore')));
}

// The phrase opened nothing: every box turns red, the reason sits under them,
// and the button waits for an edit.
const RestoreRejectedStory = Template.bind({});
RestoreRejectedStory.args = { ...ExistingUserStory.args };
RestoreRejectedStory.parameters = {
  ...ExistingUserStory.parameters,
  encryption: {
    restoreFromPhrase: async () => {
      throw new VaultError(VaultErrorCode.WRONG_SECRET_KEY, 'wrong phrase');
    },
  },
};
RestoreRejectedStory.play = async ({ canvasElement }) => {
  await playSubmitPhrase(canvasElement);
  await within(canvasElement).findByText(i18n.t('errors.vault.wrong_recovery_phrase'));
  await expect(await playFindButton(canvasElement, i18n.t('onboarding.btn_restore'))).toBeDisabled();
};

export const RestoreRejected = prepareStory(RestoreRejectedStory);

const RestoredStory = Template.bind({});
RestoredStory.args = { ...ExistingUserStory.args };
RestoredStory.parameters = ExistingUserStory.parameters;
RestoredStory.play = async ({ canvasElement }) => {
  await playSubmitPhrase(canvasElement);
  await playFindHeading(canvasElement, i18n.t('onboarding.title_enabled'));
  await within(canvasElement).findByText(i18n.t('onboarding.restored_description'));
};

export const Restored = prepareStory(RestoredStory);

const LastResortStory = Template.bind({});
LastResortStory.args = { ...ExistingUserStory.args };
LastResortStory.parameters = ExistingUserStory.parameters;
LastResortStory.play = async ({ canvasElement }) => {
  // "Lost phrase?" sits under the phrase boxes.
  await userEvent.click(await within(canvasElement).findByRole('radio', { name: new RegExp(i18n.t('onboarding.btn_restore_from_backup')) }));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_last_resort')));
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

// Replacing an identity the account already has (here a disabled one, so the
// user starts over): the server asks for a fresh second-factor sign-in (RFC 9470
// step-up) before issuing the registration challenge. It is checked at the
// commit, after the phrase is saved, because the fresh sign-in only counts for a
// few minutes. It then takes the place of the backup screen; the phrase stays
// valid, and the commit runs again once it is confirmed.
const StepUpRequiredStory = Template.bind({});
StepUpRequiredStory.args = { ...PreviousIdentityStory.args, onStepUp: fn() };
StepUpRequiredStory.parameters = {
  msw: {
    handlers: [
      ...previousIdentityHandlers,
      handlePostApiPublicKeysRegisterInit(
        () =>
          new Response(JSON.stringify({ code: 'insufficient_user_authentication', params: { max_age: 300 } }), {
            status: 401,
            headers: {
              'content-type': 'application/json',
              'www-authenticate': 'Bearer error="insufficient_user_authentication", max_age="300"',
            },
          })
      ),
    ],
  },
};
StepUpRequiredStory.play = async ({ canvasElement, args }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_start_new_identity')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await playFindHeading(canvasElement, i18n.t('onboarding.title_backup'));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_reveal')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_backup_done')));

  // The step-up replaces the backup screen: nothing else to do until it is confirmed.
  await playFindHeading(canvasElement, i18n.t('auth.step_up_title'));
  expect(within(canvasElement).queryByRole('button', { name: i18n.t('onboarding.btn_copy_clipboard') })).toBeNull();

  await userEvent.click(await playFindButton(canvasElement, i18n.t('auth.step_up_confirm')));
  expect(args.onStepUp).toHaveBeenCalled();
};

export const StepUpRequired = prepareStory(StepUpRequiredStory);
