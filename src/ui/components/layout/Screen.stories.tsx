import { Alert, Button, Checkbox, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { Icon } from '@gouvfr-lasuite/ui-kit';
import { Meta, StoryFn } from '@storybook/react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';

type ComponentType = typeof Screen;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Layouts/Screen',
  component: Screen,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: true,
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <Screen {...args} />;

// The canonical modal: illustration, title, description, one primary action.
const IllustratedStory = Template.bind({});
IllustratedStory.args = {
  illustration: 'shield-check',
  title: 'Enable encryption',
  description: (
    <p>
      To enable encryption on your account, you will need to save a <strong>recovery phrase</strong> in the next step. Without it, you could
      permanently lose access to your encrypted documents.
    </p>
  ),
  actions: <Button>Continue</Button>,
};

export const Illustrated = prepareStory(IllustratedStory);

// A step inside a flow: the way back is a small link above the title, while the
// product's cross (outside this screen) leaves the whole interface.
const WithBackStory = Template.bind({});
WithBackStory.args = {
  back: { label: 'Back', onClick: () => console.log('back') },
  title: 'Add a trusted contact',
  description: 'Search a contact by email address.',
  actions: <Button>Search</Button>,
};

export const WithBack = prepareStory(WithBackStory);

// Stacked choices: a tinted primary choice, a text-link alternative, a neutral escape.
const ChoicesStory = Template.bind({});
ChoicesStory.args = {
  illustration: 'shield-check',
  title: 'Restore your encryption',
  description: 'You already enabled encryption on another device. Choose how to restore your keys on this device.',
  actions: (
    <>
      <Button variant="secondary" icon={<Icon aria-hidden name="laptop" />}>
        Use another device
      </Button>
      <Button variant="tertiary" icon={<Icon aria-hidden name="key" />}>
        Use my recovery phrase
      </Button>
      <Button variant="tertiary" color="neutral">
        I lost my keys
      </Button>
    </>
  ),
};

export const Choices = prepareStory(ChoicesStory);

// A destructive confirmation: the acknowledgement lives inside the alert and the
// Cancel/Confirm pair sits in a right-aligned row.
const DestructiveStory = Template.bind({});
DestructiveStory.args = {
  title: 'Reset encryption',
  description:
    'You will lose access to documents encrypted with your current keys. New keys will be generated so others can share encrypted documents with you again.',
  children: (
    <Alert type={VariantType.ERROR}>
      <div className={styles.alertStack}>
        <span>If you are the only person with full access to an encrypted document, it may be lost for good.</span>
        <Checkbox label="I understand." />
      </div>
    </Alert>
  ),
  actionsLayout: 'row',
  actions: (
    <>
      <Button variant="bordered" color="neutral">
        Cancel
      </Button>
      <Button color="error" disabled>
        Reset encryption
      </Button>
    </>
  ),
};

export const Destructive = prepareStory(DestructiveStory);

// The "disabled" illustration variant.
const DisabledStory = Template.bind({});
DisabledStory.args = {
  illustration: 'shield-x',
  title: 'Encryption disabled on your account',
  description:
    'Your keys are still on this device, but your account is no longer marked as encrypted. No one can share new encrypted documents with you.',
  actions: (
    <>
      <Button variant="secondary">Re-enable encryption</Button>
      <Button variant="tertiary" color="error">
        Remove encryption from this device
      </Button>
    </>
  ),
};

export const Disabled = prepareStory(DisabledStory);
