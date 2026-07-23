import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { RecipientFingerprint, RecipientIdentity, TrustRefuseButtons } from '@encryption/src/ui/components/RecipientFingerprintControls';

type IdentityType = typeof RecipientIdentity;
const identity = StoryHelperFactory<IdentityType>();

export default {
  title: 'Preview/Components/RecipientFingerprintControls',
  component: RecipientIdentity,
  ...identity.generateMetaDefault({
    parameters: {
      layout: 'padded',
    },
  }),
} as Meta<IdentityType>;

const IdentityTemplate: StoryFn<IdentityType> = (args) => <RecipientIdentity {...args} />;

const IdentityWithLabelStory = IdentityTemplate.bind({});
IdentityWithLabelStory.args = {
  label: { name: 'Alice Martin', email: 'alice.martin@numerique.gouv.fr' },
};

export const IdentityWithLabel = identity.prepareStory(IdentityWithLabelStory);

// There is deliberately no "no label at all" case: `label` is required.
const IdentityEmailOnlyStory = IdentityTemplate.bind({});
IdentityEmailOnlyStory.args = {
  label: { email: 'alice.martin@numerique.gouv.fr' },
};

export const IdentityEmailOnly = identity.prepareStory(IdentityEmailOnlyStory);

const fingerprint = StoryHelperFactory<typeof RecipientFingerprint>();
const FingerprintTemplate: StoryFn<typeof RecipientFingerprint> = (args) => <RecipientFingerprint {...args} />;

const FingerprintStory = FingerprintTemplate.bind({});
FingerprintStory.args = {
  fingerprint: '0031712345678901234567890123456789012345',
};

export const Fingerprint = fingerprint.prepareStory(FingerprintStory);

const trust = StoryHelperFactory<typeof TrustRefuseButtons>();
const TrustTemplate: StoryFn<typeof TrustRefuseButtons> = (args) => <TrustRefuseButtons {...args} />;

const TrustButtonsStory = TrustTemplate.bind({});
TrustButtonsStory.args = { busy: false };

export const TrustButtons = trust.prepareStory(TrustButtonsStory);

const TrustButtonsBusyStory = TrustTemplate.bind({});
TrustButtonsBusyStory.args = { busy: true };

export const TrustButtonsBusy = trust.prepareStory(TrustButtonsBusyStory);
