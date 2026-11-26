import { Meta, StoryFn } from '@storybook/react';
import { expect, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { SyncIntegrityAlert } from '@encryption/src/ui/components/SyncIntegrityAlert';

type ComponentType = typeof SyncIntegrityAlert;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Components/SyncIntegrityAlert',
  component: SyncIntegrityAlert,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: 'card',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <SyncIntegrityAlert {...args} />;

const DefaultStory = Template.bind({});
DefaultStory.args = {
  onRetry: () => console.log('onRetry'),
  isRetrying: false,
};
DefaultStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('settings.sync_integrity_failed'));
  expect(await playFindButton(canvasElement, i18n.t('settings.sync_integrity_retry'))).toBeEnabled();
};

export const Default = prepareStory(DefaultStory);

// A retry is running: the button waits until the new sync settles.
const RetryingStory = Template.bind({});
RetryingStory.args = {
  onRetry: () => console.log('onRetry'),
  isRetrying: true,
};
RetryingStory.play = async ({ canvasElement }) => {
  expect(await playFindButton(canvasElement, i18n.t('settings.sync_integrity_retrying'))).toBeDisabled();
};

export const Retrying = prepareStory(RetryingStory);
