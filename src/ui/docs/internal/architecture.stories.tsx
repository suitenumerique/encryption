import { Meta, StoryFn } from '@storybook/react';
import { expect, within } from 'storybook/test';

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
// The section anchors are raw `<a id>` lines in the markdown: none may leak as
// text, and every internal link must land on a heading that carries its id.
DefaultStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByRole('heading', { name: '1. Summary' });

  expect(canvasElement.textContent).not.toContain('<a id=');

  const targets = Array.from(canvasElement.querySelectorAll<HTMLAnchorElement>('a[href^="#"]')).map((a) => a.getAttribute('href')!.slice(1));
  expect(targets.length).toBeGreaterThan(100);

  const missing = [...new Set(targets)].filter((id) => !canvasElement.ownerDocument.getElementById(id));
  expect(missing).toEqual([]);
};

export const Default = prepareStory(DefaultStory);
