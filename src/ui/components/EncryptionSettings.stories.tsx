import { Meta, StoryFn } from '@storybook/react';
import { userEvent, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { handleGetApiPublicKeys, handleGetApiPublicKeysNext } from '@encryption/src/ui/api/generated/msw.gen';
import { EncryptionSettings } from '@encryption/src/ui/components/EncryptionSettings';
import { samplePublicKey } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof EncryptionSettings;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Pages/EncryptionSettings',
  component: EncryptionSettings,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: true,
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <EncryptionSettings {...args} />;

const DEMO_USER_ID = '00000000-0000-0000-0000-000000000000';

const baseArgs = {
  getToken: async () => 'mock-jwt-token',
  userId: DEMO_USER_ID,
  userInfo: { name: 'Alice Martin', email: 'alice.martin@numerique.gouv.fr' },
  onClose: () => console.log('onClose'),
  onKeysDestroyed: () => console.log('onKeysDestroyed'),
  // The app always wires both sub-flows; without them the home shows fewer actions.
  onOpenDeviceApproval: () => console.log('onOpenDeviceApproval'),
  onOpenEmergencyAccess: () => console.log('onOpenEmergencyAccess'),
};

const directoryInSync = handleGetApiPublicKeys({ body: { keys: [{ ...samplePublicKey, user_id: DEMO_USER_ID }] } });

const InSyncStory = Template.bind({});
InSyncStory.args = { ...baseArgs };
InSyncStory.parameters = {
  msw: { handlers: [directoryInSync] },
};

InSyncStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('settings.title'));
  await playFindButton(canvasElement, i18n.t('settings.add_device'));
};

export const InSync = prepareStory(InSyncStory);

// `next_generation > 1` proves a registration existed, so re-enabling is legitimate.
const DisabledRemotelyStory = Template.bind({});
DisabledRemotelyStory.args = { ...baseArgs };
DisabledRemotelyStory.parameters = {
  msw: {
    handlers: [handleGetApiPublicKeys({ body: { keys: [] } }), handleGetApiPublicKeysNext({ body: { next_version: 2, next_generation: 2 } })],
  },
};

DisabledRemotelyStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('settings.remote_disabled_title'));
};

export const DisabledRemotely = prepareStory(DisabledRemotelyStory);

// `next_generation === 1`: nothing was ever registered, so the local keys are orphaned.
const NeverRegisteredStory = Template.bind({});
NeverRegisteredStory.args = { ...baseArgs };
NeverRegisteredStory.parameters = {
  msw: {
    handlers: [handleGetApiPublicKeys({ body: { keys: [] } }), handleGetApiPublicKeysNext({ body: { next_version: 1, next_generation: 1 } })],
  },
};

NeverRegisteredStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('settings.remote_never_title'));
};

export const NeverRegistered = prepareStory(NeverRegisteredStory);

const VaultNotReadyStory = Template.bind({});
VaultNotReadyStory.args = { ...baseArgs };
VaultNotReadyStory.parameters = {
  encryption: { isReady: false },
  msw: { handlers: [directoryInSync] },
};

export const VaultNotReady = prepareStory(VaultNotReadyStory);

const NoLocalKeysStory = Template.bind({});
NoLocalKeysStory.args = { ...baseArgs };
NoLocalKeysStory.parameters = {
  encryption: { hasKeys: async () => ({ hasKeys: false }) },
  msw: { handlers: [directoryInSync] },
};

export const NoLocalKeys = prepareStory(NoLocalKeysStory);

// The directory returns a DIFFERENT signature key from the one the vault stub holds.
const RemoteDivergedStory = Template.bind({});
RemoteDivergedStory.args = { ...baseArgs };
RemoteDivergedStory.parameters = {
  msw: {
    handlers: [
      handleGetApiPublicKeys({
        body: {
          keys: [{ ...samplePublicKey, user_id: DEMO_USER_ID, signature_public_key: `B${samplePublicKey.signature_public_key.slice(1)}` }],
        },
      }),
    ],
  },
};

RemoteDivergedStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('settings.key_mismatch'));
  await playFindButton(canvasElement, i18n.t('settings.reconcile_adopt_server'));
};

export const RemoteDiverged = prepareStory(RemoteDivergedStory);

// Adopting the server's identity deletes this device's keys: asked in-app first.
const RemoteDivergedAdoptPromptStory = Template.bind({});
RemoteDivergedAdoptPromptStory.args = { ...RemoteDivergedStory.args };
RemoteDivergedAdoptPromptStory.parameters = RemoteDivergedStory.parameters;
RemoteDivergedAdoptPromptStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('settings.reconcile_adopt_server')));
  await playFindHeading(document.body, i18n.t('settings.reconcile_adopt_title'));
  await playFindButton(document.body, i18n.t('settings.reconcile_adopt_button'));
};

export const RemoteDivergedAdoptPrompt = prepareStory(RemoteDivergedAdoptPromptStory);

// The destructive flow: a scope choice, an acknowledgement and the fingerprint
// to type before the button unlocks.
const RemoveEncryptionStory = Template.bind({});
RemoveEncryptionStory.args = { ...baseArgs };
RemoveEncryptionStory.parameters = InSyncStory.parameters;
RemoveEncryptionStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('settings.show_danger_zone')));
  await playFindHeading(canvasElement, i18n.t('settings.delete_title'));
};

export const RemoveEncryption = prepareStory(RemoveEncryptionStory);
