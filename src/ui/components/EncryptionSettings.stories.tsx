import { Meta, StoryFn } from '@storybook/react';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
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
      layout: 'padded',
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
};

const directoryInSync = handleGetApiPublicKeys({ body: { keys: [{ ...samplePublicKey, user_id: DEMO_USER_ID }] } });

const InSyncStory = Template.bind({});
InSyncStory.args = { ...baseArgs };
InSyncStory.parameters = {
  msw: { handlers: [directoryInSync] },
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

export const DisabledRemotely = prepareStory(DisabledRemotelyStory);

// `next_generation === 1`: nothing was ever registered, so the local keys are orphaned.
const NeverRegisteredStory = Template.bind({});
NeverRegisteredStory.args = { ...baseArgs };
NeverRegisteredStory.parameters = {
  msw: {
    handlers: [handleGetApiPublicKeys({ body: { keys: [] } }), handleGetApiPublicKeysNext({ body: { next_version: 1, next_generation: 1 } })],
  },
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

export const RemoteDiverged = prepareStory(RemoteDivergedStory);
