import { Meta, StoryFn } from '@storybook/react';
import { expect, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindHeading } from '@encryption/.storybook/testing';
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
// The children sit inside the styled container, so the documentation rules apply to them.
NormalStory.play = async ({ canvasElement }) => {
  const title = await playFindHeading(canvasElement, 'Page title');
  expect(title.tagName).toBe('H1');
  expect(title.closest('.docs-content')).not.toBeNull();
  await playFindHeading(canvasElement, 'Section title');
  expect(within(canvasElement).getAllByRole('listitem')).toHaveLength(2);
};

export const Normal = prepareStory(NormalStory);
