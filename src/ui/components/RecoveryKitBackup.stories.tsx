import { Meta, StoryFn } from '@storybook/react';
import { expect, userEvent } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton } from '@encryption/.storybook/testing';
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
      layout: 'centered',
      hostModal: true,
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
// The confirmation is locked until the phrase left the screen (here: revealed).
DefaultStory.play = async ({ canvasElement }) => {
  const confirm = await playFindButton(canvasElement, i18n.t('onboarding.btn_backup_done'));
  expect(confirm).toBeDisabled();
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_reveal')));
  expect(confirm).toBeEnabled();
};

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

// A trusted contact handing the grantor's phrase over: revealed, with a copy action.
const HandoverStory = Template.bind({});
HandoverStory.args = {
  ...baseArgs,
  mode: 'handover',
  title: i18n.t('emergency.reveal_title'),
  confirmLabel: i18n.t('emergency.reveal_done'),
};

export const Handover = prepareStory(HandoverStory);

// `onCancel` is what makes the second button appear.
const CancellableStory = Template.bind({});
CancellableStory.args = {
  ...baseArgs,
  onCancel: () => console.log('onCancel'),
  cancelLabel: i18n.t('onboarding.btn_cancel'),
};

export const Cancellable = prepareStory(CancellableStory);
