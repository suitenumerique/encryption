import { Meta, StoryFn } from '@storybook/react';
import { expect, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { DecimalCodeInput } from '@encryption/src/ui/components/DecimalCodeInput';
import styles from '@encryption/src/ui/components/layout/layout.module.css';

type ComponentType = typeof DecimalCodeInput;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Forms/DecimalCodeInput',
  component: DecimalCodeInput,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      // The boxes size themselves from their container (an inline-size container
      // query), so they need the width the product gives them: without the host
      // card, the centered layout shrink-wraps them to nothing.
      hostModal: 'card',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <DecimalCodeInput {...args} />;

const DefaultStory = Template.bind({});
DefaultStory.args = {
  groupCount: 8,
  groupSize: 5,
};
// Eight empty numeric boxes of five digits each, none flagged as refused.
DefaultStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  for (let group = 1; group <= 8; group++) {
    const box = canvas.getByLabelText(`code group ${group}`) as HTMLInputElement;
    expect(box).toHaveValue('');
    expect(box).toHaveAttribute('inputmode', 'numeric');
    expect(box.maxLength).toBe(5);
  }
  expect(canvas.queryByLabelText('code group 9')).toBeNull();
  expect(canvasElement.querySelector(`.${styles.fingerprintInvalid}`)).toBeNull();
};

export const Default = prepareStory(DefaultStory);
