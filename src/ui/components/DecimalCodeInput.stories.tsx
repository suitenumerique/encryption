import { Meta, StoryFn } from '@storybook/react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { DecimalCodeInput } from '@encryption/src/ui/components/DecimalCodeInput';

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

export const Default = prepareStory(DefaultStory);
