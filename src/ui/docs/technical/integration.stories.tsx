import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { TechnicalDocsPage } from '@encryption/src/ui/docs/TechnicalDocsPage';
import Content from '@encryption/src/ui/docs/technical/integration.mdx';

type ComponentType = typeof Content;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Docs/TechnicalIntegration',
  component: Content,
  ...generateMetaDefault({
    parameters: {
      layout: 'fullscreen',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = () => <TechnicalDocsPage />;

const DefaultStory = Template.bind({});
DefaultStory.args = {};

export const Default = prepareStory(DefaultStory);
