import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { DecimalCodeInput } from '@encryption/src/ui/components/DecimalCodeInput';

type ComponentType = typeof DecimalCodeInput;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Forms/DecimalCodeInput',
  component: DecimalCodeInput,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <DecimalCodeInput {...args} />;

const DefaultStory = Template.bind({});
DefaultStory.args = {
  groupCount: 8,
  groupSize: 5,
};

export const Default = prepareStory(DefaultStory);
