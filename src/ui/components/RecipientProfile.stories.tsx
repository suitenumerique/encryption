import { Meta, StoryFn } from '@storybook/react';
import { within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { MSG_VAULT_FETCH_PUBLIC_KEYS, MSG_VAULT_GET_KNOWN_FINGERPRINTS } from '@encryption/src/shared/constants';
import { RecipientProfile } from '@encryption/src/ui/components/RecipientProfile';
import { sampleFingerprint, samplePublicKey } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof RecipientProfile;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Pages/RecipientProfile',
  component: RecipientProfile,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: true,
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <RecipientProfile {...args} />;

const RECIPIENT_SUB = 'bob@numerique.gouv.fr';

const baseArgs = {
  userId: RECIPIENT_SUB,
  label: { name: 'Bob Dupont', email: 'bob.dupont@numerique.gouv.fr' },
};

// Lookups go through the VAULT (postMessage), not HTTP, so scenarios override
// `request` instead of using MSW handlers.
const registeredRecipient = {
  users: { [RECIPIENT_SUB]: { userId: samplePublicKey.user_id, identityFingerprint: sampleFingerprint, verified: true } },
};

function vaultReturning(users: unknown, fingerprints: unknown = {}) {
  return async (type: string) => (type === MSG_VAULT_FETCH_PUBLIC_KEYS ? users : type === MSG_VAULT_GET_KNOWN_FINGERPRINTS ? { fingerprints } : {});
}

// A first encounter is deliberately 'unknown': never trust-on-first-use.
const UnknownStory = Template.bind({});
UnknownStory.args = { ...baseArgs };
UnknownStory.parameters = {
  encryption: { request: vaultReturning(registeredRecipient) },
};

export const Unknown = prepareStory(UnknownStory);

const LoadingStory = Template.bind({});
LoadingStory.args = { ...baseArgs };
LoadingStory.parameters = {
  encryption: { request: () => new Promise<unknown>(() => {}) },
};

export const Loading = prepareStory(LoadingStory);

const NotRegisteredStory = Template.bind({});
NotRegisteredStory.args = { ...baseArgs };
NotRegisteredStory.parameters = {
  encryption: { request: vaultReturning({ users: {} }) },
};

export const NotRegistered = prepareStory(NotRegisteredStory);

// `label` is required, but its `name` is not.
const EmailOnlyStory = Template.bind({});
EmailOnlyStory.args = { userId: RECIPIENT_SUB, label: { email: 'bob.dupont@numerique.gouv.fr' } };
EmailOnlyStory.parameters = {
  encryption: { request: vaultReturning(registeredRecipient) },
};

export const EmailOnly = prepareStory(EmailOnlyStory);

const NoRecipientStory = Template.bind({});
NoRecipientStory.args = { userId: null };

export const NoRecipient = prepareStory(NoRecipientStory);

const TrustedStory = Template.bind({});
TrustedStory.args = { ...baseArgs };
TrustedStory.parameters = {
  encryption: {
    request: vaultReturning(registeredRecipient, { [samplePublicKey.user_id]: { fingerprint: sampleFingerprint, status: 'trusted' } }),
  },
};

export const Trusted = prepareStory(TrustedStory);

const RefusedStory = Template.bind({});
RefusedStory.args = { ...baseArgs };
RefusedStory.parameters = {
  encryption: {
    request: vaultReturning(registeredRecipient, { [samplePublicKey.user_id]: { fingerprint: sampleFingerprint, status: 'refused' } }),
  },
};

export const Refused = prepareStory(RefusedStory);

// Trusted once, but on another key: the registry now shows a different
// fingerprint, so the old decision is void and both choices come back.
const KeyChangedStory = Template.bind({});
KeyChangedStory.args = { ...baseArgs };
KeyChangedStory.parameters = {
  encryption: {
    request: vaultReturning(registeredRecipient, {
      [samplePublicKey.user_id]: { fingerprint: '00000 00000 00000 00000 00000 00000 00000 00001', status: 'trusted' },
    }),
  },
};
KeyChangedStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('profile.decision_changed'));
  await playFindButton(canvasElement, i18n.t('profile.btn_trust'));
  await playFindButton(canvasElement, i18n.t('profile.btn_refuse'));
};

export const KeyChanged = prepareStory(KeyChangedStory);
