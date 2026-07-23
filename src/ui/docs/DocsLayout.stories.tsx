import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { DocsLayout } from '@encryption/src/ui/docs/DocsLayout';

type ComponentType = typeof DocsLayout;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Layouts/DocsPages',
  component: DocsLayout,
  ...generateMetaDefault({
    parameters: {
      layout: 'fullscreen',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <DocsLayout {...args} />;

const NormalStory = Template.bind({});
NormalStory.args = {
  children: (
    <>
      <h1>Page title</h1>
      <p>A sample paragraph, to check the line height, measure and text colour the documentation layout applies.</p>
      <h2>Section title</h2>
      <ul>
        <li>First list item</li>
        <li>Second list item</li>
      </ul>
    </>
  ),
};

export const Normal = prepareStory(NormalStory);
