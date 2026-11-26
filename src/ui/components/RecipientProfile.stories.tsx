import { Meta, StoryFn } from '@storybook/react';
import { expect, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { MSG_VAULT_FETCH_PUBLIC_KEYS, MSG_VAULT_GET_KNOWN_FINGERPRINTS } from '@encryption/src/shared/constants';
import { RecipientProfile } from '@encryption/src/ui/components/RecipientProfile';
import layoutStyles from '@encryption/src/ui/components/layout/layout.module.css';
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
const fingerprintLabel = (sampleFingerprint.match(/\d{5}/g) ?? []).join(' ');

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
UnknownStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await playFindHeading(canvasElement, i18n.t('profile.title'));
  await canvas.findByText(i18n.t('profile.compare_instruction'));
  canvas.getByLabelText(fingerprintLabel);
  expect(canvas.queryByText(i18n.t('profile.decision_trusted'))).toBeNull();
  expect(canvas.queryByText(i18n.t('profile.decision_refused'))).toBeNull();
  await playFindButton(canvasElement, i18n.t('profile.btn_trust'));
  await playFindButton(canvasElement, i18n.t('profile.btn_refuse'));
};

export const Unknown = prepareStory(UnknownStory);

const LoadingStory = Template.bind({});
LoadingStory.args = { ...baseArgs };
LoadingStory.parameters = {
  encryption: { request: () => new Promise<unknown>(() => {}) },
};
LoadingStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByRole('status');
  expect(within(canvasElement).queryByRole('heading')).toBeNull();
};

export const Loading = prepareStory(LoadingStory);

const NotRegisteredStory = Template.bind({});
NotRegisteredStory.args = { ...baseArgs };
NotRegisteredStory.parameters = {
  encryption: { request: vaultReturning({ users: {} }) },
};
NotRegisteredStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('profile.no_key'));
  canvas.getByText(baseArgs.label.name);
  expect(canvas.queryByLabelText(fingerprintLabel)).toBeNull();
  expect(canvas.queryByRole('button', { name: i18n.t('profile.btn_trust') })).toBeNull();
  expect(canvas.queryByRole('button', { name: i18n.t('profile.btn_refuse') })).toBeNull();
};

export const NotRegistered = prepareStory(NotRegisteredStory);

// `label` is required, but its `name` is not.
const EmailOnlyStory = Template.bind({});
EmailOnlyStory.args = { userId: RECIPIENT_SUB, label: { email: 'bob.dupont@numerique.gouv.fr' } };
EmailOnlyStory.parameters = {
  encryption: { request: vaultReturning(registeredRecipient) },
};
// The email is the card's only line, shown once.
EmailOnlyStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByLabelText(fingerprintLabel);
  expect(canvas.getAllByText(baseArgs.label.email)).toHaveLength(1);
  await playFindButton(canvasElement, i18n.t('profile.btn_trust'));
};

export const EmailOnly = prepareStory(EmailOnlyStory);

const NoRecipientStory = Template.bind({});
NoRecipientStory.args = { userId: null };
// No one to look up: nothing to verify and no decision to offer.
NoRecipientStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('profile.no_key'));
  // No empty identity card above the hint.
  expect(canvasElement.querySelector(`.${layoutStyles.identity}`)).toBeNull();
  expect(canvas.queryByRole('button', { name: i18n.t('profile.btn_trust') })).toBeNull();
  expect(canvas.queryByRole('button', { name: i18n.t('profile.btn_refuse') })).toBeNull();
};

export const NoRecipient = prepareStory(NoRecipientStory);

const TrustedStory = Template.bind({});
TrustedStory.args = { ...baseArgs };
TrustedStory.parameters = {
  encryption: {
    request: vaultReturning(registeredRecipient, { [samplePublicKey.user_id]: { fingerprint: sampleFingerprint, status: 'trusted' } }),
  },
};
// Only the reversal is offered.
TrustedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('profile.decision_trusted'));
  await playFindButton(canvasElement, i18n.t('profile.btn_refuse'));
  expect(canvas.queryByRole('button', { name: i18n.t('profile.btn_trust') })).toBeNull();
};

export const Trusted = prepareStory(TrustedStory);

const RefusedStory = Template.bind({});
RefusedStory.args = { ...baseArgs };
RefusedStory.parameters = {
  encryption: {
    request: vaultReturning(registeredRecipient, { [samplePublicKey.user_id]: { fingerprint: sampleFingerprint, status: 'refused' } }),
  },
};
// Only the reversal is offered.
RefusedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('profile.decision_refused'));
  await playFindButton(canvasElement, i18n.t('profile.btn_trust'));
  expect(canvas.queryByRole('button', { name: i18n.t('profile.btn_refuse') })).toBeNull();
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
