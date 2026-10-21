import { Meta, StoryFn } from '@storybook/react';
import { expect, userEvent, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import i18n from '@encryption/src/i18n';
import { RecoveryPhraseInput } from '@encryption/src/ui/components/RecoveryPhraseInput';
import styles from '@encryption/src/ui/components/layout/layout.module.css';

type ComponentType = typeof RecoveryPhraseInput;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Forms/RecoveryPhraseInput',
  component: RecoveryPhraseInput,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: 'card',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <RecoveryPhraseInput {...args} />;

const DefaultStory = Template.bind({});
DefaultStory.args = {
  wordCount: 24,
};
// 24 empty boxes, masked until the toggle reveals them, with no word flagged yet.
DefaultStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  for (let i = 1; i <= 24; i++) {
    const box = canvas.getByLabelText(i18n.t('onboarding.word_label', { number: i }));
    expect(box).toHaveValue('');
    expect(box).toHaveAttribute('type', 'password');
  }
  expect(canvas.queryByLabelText(i18n.t('onboarding.word_label', { number: 25 }))).toBeNull();
  expect(canvas.getByRole('button', { name: i18n.t('onboarding.reveal_words') })).toHaveAttribute('aria-pressed', 'false');
  expect(canvasElement.querySelector(`.${styles.inputInvalid}`)).toBeNull();
  expect(canvas.queryByText(i18n.t('onboarding.invalid_word_hint'))).toBeNull();
};

export const Default = prepareStory(DefaultStory);

// French words are typed with composed accents while the wordlist is stored
// decomposed: the longest ones fill a box without overflowing and none is
// flagged as a typo. The last box holds a real typo so the hint shows once.
const AccentedWordsStory = Template.bind({});
AccentedWordsStory.args = { wordCount: 6, onChange: () => undefined };
AccentedWordsStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  const words = ['bénéfice', 'cérébral', 'désobéir', 'éléphant', 'énumérer', 'bénéfise'];
  for (const [i, word] of words.entries()) {
    const box = canvas.getByLabelText(`Word ${i + 1}`);
    await userEvent.type(box, word);
    await userEvent.tab();
    expect((box as HTMLInputElement).scrollWidth).toBeLessThanOrEqual((box as HTMLInputElement).clientWidth);
  }
  expect(canvasElement.querySelectorAll(`.${styles.inputInvalid}`)).toHaveLength(1);
  expect(canvas.getByLabelText('Word 6')).toHaveClass(styles.inputInvalid);
};

export const AccentedWords = prepareStory(AccentedWordsStory);
