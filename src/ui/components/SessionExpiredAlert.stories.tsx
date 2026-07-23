import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';

type ComponentType = typeof SessionExpiredAlert;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Components/SessionExpiredAlert',
  component: SessionExpiredAlert,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <SessionExpiredAlert {...args} />;

const DefaultStory = Template.bind({});
DefaultStory.args = {
  isAuthenticating: false,
};
DefaultStory.play = async ({ canvasElement }) => {
  await playFindButton(canvasElement, i18n.t('auth.reconnect', 'Reconnect'));
};

export const Default = prepareStory(DefaultStory);

const AuthenticatingStory = Template.bind({});
AuthenticatingStory.args = {
  isAuthenticating: true,
};

export const Authenticating = prepareStory(AuthenticatingStory);
