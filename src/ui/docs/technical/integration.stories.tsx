import { Meta, StoryFn } from '@storybook/react';

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
      // Only the first screen: enough to catch a styling change, any text edit would shift everything below it.
      chromatic: { cropToViewport: true },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = () => <TechnicalDocsPage />;

const DefaultStory = Template.bind({});
DefaultStory.args = {};

export const Default = prepareStory(DefaultStory);
