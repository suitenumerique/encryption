import { Meta, StoryFn } from '@storybook/react';
import { expect, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { EmergencySignedOutPrompt } from '@encryption/src/ui/components/EmergencySignedOutPrompt';

type ComponentType = typeof EmergencySignedOutPrompt;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Modals/EmergencySignedOutPrompt',
  component: EmergencySignedOutPrompt,
  ...generateMetaDefault({ parameters: { layout: 'centered', hostModal: true } }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <EmergencySignedOutPrompt {...args} />;

// A trusted contact asked to recover the user's data: the alert shows before any sign-in.
const RecoveryStory = Template.bind({});
RecoveryStory.args = {
  recovery: true,
  onSignIn: () => console.log('onSignIn'),
};
RecoveryStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('emergency.prompt_recovery_title'));
  await within(canvasElement).findByText(i18n.t('emergency.prompt_signed_out_recovery'));
  await playFindButton(canvasElement, i18n.t('emergency.btn_prompt_sign_in'));
  expect(within(canvasElement).queryByText(i18n.t('auth.required_title'))).toBeNull();
};

export const Recovery = prepareStory(RecoveryStory);

// Only an invitation is pending.
const InvitationStory = Template.bind({});
InvitationStory.args = {
  recovery: false,
  onSignIn: () => console.log('onSignIn'),
};
InvitationStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('emergency.prompt_invite_title'));
  await within(canvasElement).findByText(i18n.t('emergency.prompt_signed_out_invite'));
  await playFindButton(canvasElement, i18n.t('emergency.btn_prompt_sign_in'));
};

export const Invitation = prepareStory(InvitationStory);
