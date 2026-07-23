import { Meta, StoryFn } from '@storybook/react';
import { userEvent } from '@storybook/test';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { handleGetApiPublicKeys, handleGetApiPublicKeysNext } from '@encryption/src/ui/api/generated/msw.gen';
import { ModalEncryptionOnboarding } from '@encryption/src/ui/components/ModalEncryptionOnboarding';
import { samplePublicKey } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof ModalEncryptionOnboarding;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Pages/EncryptionOnboarding',
  component: ModalEncryptionOnboarding,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
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
PreviousIdentityStory.parameters = {
  msw: {
    handlers: [handleGetApiPublicKeys({ body: { keys: [] } }), handleGetApiPublicKeysNext({ body: { next_version: 3, next_generation: 2 } })],
  },
};
PreviousIdentityStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_previous_identity'));
};

export const PreviousIdentity = prepareStory(PreviousIdentityStory);

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
