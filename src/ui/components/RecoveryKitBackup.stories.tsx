import { Meta, StoryFn } from '@storybook/react';
import { expect, userEvent } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { RecoveryKitBackup } from '@encryption/src/ui/components/RecoveryKitBackup';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
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

// The phrase stays hidden until asked for, and the confirmation is locked until
// the phrase left the screen through one of the actions.
const DefaultStory = Template.bind({});
DefaultStory.args = { ...baseArgs };
DefaultStory.play = async ({ canvasElement }) => {
  expect(await playFindButton(canvasElement, i18n.t('onboarding.btn_backup_done'))).toBeDisabled();
  await playFindButton(canvasElement, i18n.t('onboarding.btn_reveal'));
  expect(canvasElement.querySelector(`.${styles.words}`)).toBeNull();
};

export const Default = prepareStory(DefaultStory);

// Reading the phrase on screen counts as having it: the word grid replaces the
// reveal button and the confirmation unlocks.
const RevealedStory = Template.bind({});
RevealedStory.args = { ...baseArgs };
RevealedStory.play = async ({ canvasElement }) => {
  const confirm = await playFindButton(canvasElement, i18n.t('onboarding.btn_backup_done'));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_reveal')));
  expect(canvasElement.querySelector(`.${styles.words}`)).not.toBeNull();
  expect(confirm).toBeEnabled();
};

export const Revealed = prepareStory(RevealedStory);

const BusyStory = Template.bind({});
BusyStory.args = { ...baseArgs, isBusy: true };

export const Busy = prepareStory(BusyStory);

// A commit error only ever follows a confirm attempt, which required the phrase
// to have left the screen first: reproduce that state so the retry is enabled.
const ErroredStory = Template.bind({});
ErroredStory.args = {
  ...baseArgs,
  error: 'The server is temporarily unavailable. Try again.',
};
ErroredStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_reveal')));
  expect(await playFindButton(canvasElement, i18n.t('onboarding.btn_backup_done'))).toBeEnabled();
  expect(canvasElement.querySelector('.c__alert')).not.toBeNull();
};

export const Errored = prepareStory(ErroredStory);

// A trusted contact handing the grantor's phrase over: revealed, with a copy action.
const HandoverStory = Template.bind({});
HandoverStory.args = {
  ...baseArgs,
  mode: 'handover',
  // Reached from the emergency access list: nothing was minted here, so a step
  // back is harmless. The owner's own backup screens have no such link: once a
  // phrase exists, leaving goes through the cross and its confirmation.
  back: { label: i18n.t('emergency.btn_back_to_list'), onClick: () => console.log('back') },
  title: i18n.t('emergency.reveal_title'),
  confirmLabel: i18n.t('emergency.reveal_done'),
};

export const Handover = prepareStory(HandoverStory);
