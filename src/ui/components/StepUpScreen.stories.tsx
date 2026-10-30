import { Meta, StoryFn } from '@storybook/react';
import { expect, fn, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { StepUpScreen } from '@encryption/src/ui/components/StepUpScreen';

type ComponentType = typeof StepUpScreen;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Components/StepUpScreen',
  component: StepUpScreen,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: true,
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <StepUpScreen {...args} />;

// The server refused a sensitive action for want of a fresh second factor.
const RequiredStory = Template.bind({});
RequiredStory.args = {
  state: 'required',
  isAuthenticating: false,
};
RequiredStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('auth.step_up_title'));
  await within(canvasElement).findByText(i18n.t('auth.step_up_required'));
  await playFindButton(canvasElement, i18n.t('auth.step_up_confirm'));
};

export const Required = prepareStory(RequiredStory);

// The step-up came back without a second factor: only the user can enable one.
const NoSecondFactorStory = Template.bind({});
NoSecondFactorStory.args = {
  state: 'no_second_factor',
  isAuthenticating: false,
};
NoSecondFactorStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('auth.step_up_no_second_factor'));
  await playFindButton(canvasElement, i18n.t('auth.step_up_retry'));
};

export const NoSecondFactor = prepareStory(NoSecondFactorStory);

// The step-up tab is out: the button opens it again, Cancel stops waiting, and the hint says where to look.
const AuthenticatingStory = Template.bind({});
AuthenticatingStory.args = {
  onCancel: fn(),
  state: 'required',
  isAuthenticating: true,
};
AuthenticatingStory.play = async ({ canvasElement }) => {
  expect(await playFindButton(canvasElement, i18n.t('auth.reopen'))).toBeEnabled();
  expect(await playFindButton(canvasElement, i18n.t('auth.cancel'))).toBeEnabled();
  await within(canvasElement).findByText(i18n.t('auth.finish_in_tab'));
};

export const Authenticating = prepareStory(AuthenticatingStory);
