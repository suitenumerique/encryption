import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { ArchitectureDoc } from '@encryption/src/ui/docs/internal/ArchitectureDoc';

type ComponentType = typeof ArchitectureDoc;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Docs/Architecture',
  component: ArchitectureDoc,
  ...generateMetaDefault({
    parameters: {
      layout: 'fullscreen',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = () => <ArchitectureDoc />;

const DefaultStory = Template.bind({});
DefaultStory.args = {};

export const Default = prepareStory(DefaultStory);
