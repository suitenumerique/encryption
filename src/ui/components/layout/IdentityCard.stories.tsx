import { Meta, StoryFn } from '@storybook/react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { Chip, CopyFingerprintButton, IdentityCard } from '@encryption/src/ui/components/layout/IdentityCard';
import { sampleFingerprint } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof IdentityCard;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Components/IdentityCard',
  component: IdentityCard,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: 'card',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <IdentityCard {...args} />;

const baseArgs = {
  name: 'Amandine Salambo',
  secondary: 'amandine.salambo@numerique.gouv.fr',
  fingerprint: sampleFingerprint,
};

const DefaultStory = Template.bind({});
DefaultStory.args = { ...baseArgs };

export const Default = prepareStory(DefaultStory);

// One's own identity, as settings shows it: the copy control is for sending
// the fingerprint to a contact, so it never appears on a contact's card.
const OwnIdentityStory = Template.bind({});
OwnIdentityStory.args = { ...baseArgs, aside: <CopyFingerprintButton fingerprint={sampleFingerprint} /> };

export const OwnIdentity = prepareStory(OwnIdentityStory);

const EmailOnlyStory = Template.bind({});
EmailOnlyStory.args = { name: 'amandine.salambo@numerique.gouv.fr', fingerprint: sampleFingerprint };

export const EmailOnly = prepareStory(EmailOnlyStory);

// A changed key: the border and the digit boxes take the warning tint.
const KeyMismatchStory = Template.bind({});
KeyMismatchStory.args = {
  ...baseArgs,
  tone: 'warning',
  aside: (
    <Chip tone="warning" icon="warning">
      Key mismatch
    </Chip>
  ),
};

export const KeyMismatch = prepareStory(KeyMismatchStory);

const TrustedStory = Template.bind({});
TrustedStory.args = {
  ...baseArgs,
  tone: 'success',
  aside: (
    <Chip tone="success" icon="check_circle">
      Trusted
    </Chip>
  ),
};

export const Trusted = prepareStory(TrustedStory);

const RefusedStory = Template.bind({});
RefusedStory.args = {
  ...baseArgs,
  tone: 'error',
  aside: (
    <Chip tone="error" icon="block">
      Refused
    </Chip>
  ),
};

export const Refused = prepareStory(RefusedStory);

// No fingerprint (a contact who has not set up encryption yet).
const WithoutFingerprintStory = Template.bind({});
WithoutFingerprintStory.args = { name: 'Amandine Salambo', secondary: 'amandine.salambo@numerique.gouv.fr' };

export const WithoutFingerprint = prepareStory(WithoutFingerprintStory);
