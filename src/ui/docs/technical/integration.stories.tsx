import { Meta, StoryFn } from '@storybook/react';
import { expect, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindHeading } from '@encryption/.storybook/testing';
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
      // Only the first screen: enough to catch a styling change, any text edit would shift everything below it.
      chromatic: { cropToViewport: true },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = () => <TechnicalDocsPage />;

const DefaultStory = Template.bind({});
DefaultStory.args = {};
// The guide renders through the MDX components: its title, the domains table, and highlighted code fences.
DefaultStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, /^Integration guide/);
  await playFindHeading(canvasElement, 'Architecture');
  expect(within(canvasElement).getAllByRole('table').length).toBeGreaterThan(0);
  expect(canvasElement.querySelector('.docs-content .hljs')).not.toBeNull();
};

export const Default = prepareStory(DefaultStory);
