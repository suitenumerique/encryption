import { Meta, StoryFn } from '@storybook/react';
import { expect, within } from 'storybook/test';

import { commonDocumentsParameters } from '@encryption/.storybook/document';
import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { RecoveryKitSheet } from '@encryption/src/ui/documents/RecoveryKitSheet';
import { sampleRecoveryPhrase } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof RecoveryKitSheet;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Documents/RecoveryKit',
  component: RecoveryKitSheet,
  ...generateMetaDefault({
    parameters: {
      ...commonDocumentsParameters,
    },
  }),
} as Meta<ComponentType>;

const sampleWords = sampleRecoveryPhrase.split(' ');

// The sheet on a grey desk, as a PDF reader would show the printed page. The
// language follows the Storybook locale toolbar.
const Template: StoryFn<ComponentType> = (args) => (
  <div style={{ display: 'flex', justifyContent: 'center', padding: 24, minHeight: '100vh', background: '#525659' }}>
    <div style={{ boxShadow: '0 2px 8px rgba(0, 0, 0, 0.5)' }}>
      <RecoveryKitSheet {...args} />
    </div>
  </div>
);

const DefaultStory = Template.bind({});
DefaultStory.args = { words: sampleWords, domain: 'encryption.numerique.gouv.fr' };
DefaultStory.play = async ({ canvasElement }) => {
  const sheet = await within(canvasElement).findByRole('article');
  const items = within(sheet).getAllByRole('listitem');

  await expect(items).toHaveLength(sampleWords.length);
  for (const [index, word] of sampleWords.entries()) {
    await expect(items[index]).toHaveTextContent(`${index + 1}.${word}`);
  }
};

export const Default = prepareStory(DefaultStory);
