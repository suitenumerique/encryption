import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { RecoveryPhraseInput } from '@encryption/src/ui/components/RecoveryPhraseInput';

type ComponentType = typeof RecoveryPhraseInput;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Forms/RecoveryPhraseInput',
  component: RecoveryPhraseInput,
  ...generateMetaDefault({
    parameters: {
      layout: 'padded',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <RecoveryPhraseInput {...args} />;

const DefaultStory = Template.bind({});
DefaultStory.args = {
  wordCount: 24,
};

export const Default = prepareStory(DefaultStory);
