import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { UserDocsPage } from '@encryption/src/ui/docs/UserDocsPage';

type ComponentType = typeof UserDocsPage;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Docs/UserFaq',
  component: UserDocsPage,
  ...generateMetaDefault({
    parameters: {
      layout: 'fullscreen',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = () => <UserDocsPage />;

// The rendered locale follows the toolbar.
const DefaultStory = Template.bind({});
DefaultStory.args = {};

export const Default = prepareStory(DefaultStory);
