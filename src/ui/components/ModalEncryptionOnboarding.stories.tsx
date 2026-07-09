import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import { ModalEncryptionOnboarding } from '@encryption/src/ui/components/ModalEncryptionOnboarding';

type ComponentType = typeof ModalEncryptionOnboarding;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Interface/ModalEncryptionOnboarding',
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

// --- New user (no existing keys) ---

const NewUserStory = Template.bind({});
NewUserStory.args = {
  getToken: async () => 'mock-jwt-token',
  userId: '00000000-0000-0000-0000-000000000000',
  onClose: () => console.log('onClose'),
  onSuccess: (pk) => console.log('onSuccess', pk),
  hasExistingBackendKey: false,
};
NewUserStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, /activer le chiffrement/i);
};

export const NewUser = prepareStory(NewUserStory);

// --- Existing user (has backend key, needs restore or fresh start) ---

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
ExistingUserStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, /configuration existante/i);
  await playFindButton(canvasElement, /restaurer les clés/i);
};

export const ExistingUser = prepareStory(ExistingUserStory);
