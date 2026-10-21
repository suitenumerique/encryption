import { Meta, StoryFn } from '@storybook/react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { UserDocsPage } from '@encryption/src/ui/docs/UserDocsPage';

type ComponentType = typeof UserDocsPage;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Docs/UserFaq',
  component: UserDocsPage,
  ...generateMetaDefault({
    parameters: {
      layout: 'fullscreen',
      // Only the first screen: enough to catch a styling change, any text edit would shift everything below it.
      chromatic: { cropToViewport: true },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = () => <UserDocsPage />;

// The rendered locale follows the toolbar.
const DefaultStory = Template.bind({});
DefaultStory.args = {};
// The lazily loaded FAQ of the active locale, not the empty Suspense fallback.
DefaultStory.play = async ({ canvasElement }) => {
  const english = i18n.language.startsWith('en');
  await playFindHeading(canvasElement, english ? /^Frequently asked questions/ : /^Foire aux questions/, { timeout: 5000 });
  await playFindHeading(canvasElement, english ? 'What is end-to-end encryption?' : "Qu'est-ce que le chiffrement de bout en bout ?");
};

export const Default = prepareStory(DefaultStory);
