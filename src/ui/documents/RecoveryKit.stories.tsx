import { Meta, StoryFn } from '@storybook/react';

import { WithDocumentRenderer } from '@encryption/.storybook/WithDocumentRenderer';
import { commonDocumentsParameters } from '@encryption/.storybook/document';
import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindDocumentStructure } from '@encryption/.storybook/testing';
import { RecoveryKitDocument } from '@encryption/src/ui/documents/RecoveryKitDocument';
import { sampleRecoveryPhrase } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof RecoveryKitDocument;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Documents/RecoveryKit',
  component: RecoveryKitDocument,
  ...generateMetaDefault({
    parameters: {
      ...commonDocumentsParameters,
    },
  }),
} as Meta<ComponentType>;

// The language follows the Storybook locale toolbar (same as the email stories),
// so one story shows both locales rather than duplicating them.
const Template: StoryFn<ComponentType> = (_args, { globals }) => {
  const lang = (globals.locale as string) ?? 'en';

  return <RecoveryKitDocument words={sampleRecoveryPhrase.split(' ')} lang={lang} domain="encryption.numerique.gouv.fr" />;
};

const DefaultStory = Template.bind({});
DefaultStory.decorators = [WithDocumentRenderer];
DefaultStory.play = async ({ canvasElement }) => {
  await playFindDocumentStructure(canvasElement);
};

export const Default = prepareStory(DefaultStory);
