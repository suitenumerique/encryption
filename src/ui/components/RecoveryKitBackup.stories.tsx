import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import i18n from '@encryption/src/i18n';
import { RecoveryKitBackup } from '@encryption/src/ui/components/RecoveryKitBackup';
import { sampleRecoveryPhrase } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof RecoveryKitBackup;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Components/RecoveryKitBackup',
  component: RecoveryKitBackup,
  ...generateMetaDefault({
    parameters: {
      layout: 'padded',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <RecoveryKitBackup {...args} />;

const baseArgs = {
  passphrase: sampleRecoveryPhrase,
  parentOrigin: 'https://docs.example.gouv.fr',
  confirmLabel: i18n.t('onboarding.btn_backup_done'),
  busyLabel: i18n.t('onboarding.finalizing'),
  onConfirm: () => console.log('onConfirm'),
};

const DefaultStory = Template.bind({});
DefaultStory.args = { ...baseArgs };

export const Default = prepareStory(DefaultStory);

const BusyStory = Template.bind({});
BusyStory.args = { ...baseArgs, isBusy: true };

export const Busy = prepareStory(BusyStory);

// The phrase stays on screen: it is the only copy.
const ErroredStory = Template.bind({});
ErroredStory.args = {
  ...baseArgs,
  error: 'The server is temporarily unavailable. Try again.',
};

export const Errored = prepareStory(ErroredStory);

// `onCancel` is what makes the second button appear.
const CancellableStory = Template.bind({});
CancellableStory.args = {
  ...baseArgs,
  onCancel: () => console.log('onCancel'),
  cancelLabel: i18n.t('onboarding.btn_cancel'),
};

export const Cancellable = prepareStory(CancellableStory);
