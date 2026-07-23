import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { FingerprintDisplay } from '@encryption/src/ui/components/FingerprintDisplay';

type ComponentType = typeof FingerprintDisplay;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Components/FingerprintDisplay',
  component: FingerprintDisplay,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <FingerprintDisplay {...args} />;

const DefaultStory = Template.bind({});
DefaultStory.args = {
  fingerprint: '0031712345678901234567890123456789012345',
};

export const Default = prepareStory(DefaultStory);

const PreGroupedStory = Template.bind({});
PreGroupedStory.args = {
  fingerprint: '00317 12345 67890 12345 67890 12345 67890 12345',
};

export const PreGrouped = prepareStory(PreGroupedStory);
