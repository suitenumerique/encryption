import { Meta, StoryFn } from '@storybook/react';

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
      // Only the first screen: enough to catch a styling change, while the whole page exceeds
      // Chromatic's capture limit (25M pixels) and any text edit would shift everything below it.
      chromatic: { cropToViewport: true },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = () => <ArchitectureDoc />;

const DefaultStory = Template.bind({});
DefaultStory.args = {};

export const Default = prepareStory(DefaultStory);
