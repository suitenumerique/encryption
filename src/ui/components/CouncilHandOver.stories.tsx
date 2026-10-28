import { Meta, StoryFn } from '@storybook/react';
import { expect, userEvent, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { MSG_VAULT_COUNCIL_CONTRIBUTE } from '@encryption/src/shared/constants';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import {
  handleGetApiCouncilRecoveryRequestsByIdCustodian,
  handlePostApiCouncilRecoveryRequestsByIdContribute,
} from '@encryption/src/ui/api/generated/msw.gen';
import { CouncilHandOver } from '@encryption/src/ui/components/CouncilHandOver';
import { COUNCIL_LABEL } from '@encryption/src/ui/testing/council-stories';
import { sampleCouncilEscrowRecord, sampleFingerprint, samplePublicKey } from '@encryption/src/ui/testing/fixtures';
import { defaultVaultRequest } from '@encryption/src/ui/testing/mock-encryption';

type ComponentType = typeof CouncilHandOver;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

const NOW = Date.UTC(2026, 9, 28, 9);

export default {
  title: 'Preview/Modals/CouncilHandOver',
  component: CouncilHandOver,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: true,
      date: new Date(NOW),
      docs: {
        description: {
          component:
            "A custodian hands over their share of a request: remotely as an approval, or in person to the code read on the person's own screen (camera or typed digits).",
        },
      },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <CouncilHandOver {...args} />;

const request = {
  id: '5d6e7f80-0000-4000-8000-000000000001',
  user_name: 'Ursula Roux',
  user_email: 'ursula.roux@numerique.gouv.fr',
  created_at_millis: NOW,
  expires_at_millis: NOW + 7 * 24 * 60 * 60 * 1000,
  stage: 'collecting' as const,
  contributors: [],
  my_contribution: 'none' as const,
  can_contribute: true,
};

const handlers = (stage: 'awaiting_meeting' | 'released') => ({
  msw: {
    handlers: [
      handleGetApiCouncilRecoveryRequestsByIdCustodian({
        body: {
          id: request.id,
          council_id: 'dinum',
          user_id: '00000000-0000-0000-0000-000000000000',
          user_name: request.user_name,
          user_email: request.user_email,
          ephemeral_public_key: samplePublicKey.encryption_public_key,
          stage: 'collecting',
          meeting_required: false,
          escrow: sampleCouncilEscrowRecord,
          capsule: { kind: 'direct', generation: 1, slot: 1, wrapped_share: samplePublicKey.key_binding_signature },
        },
      }),
      handlePostApiCouncilRecoveryRequestsByIdContribute({ body: { stage } }),
    ],
  },
});

const baseArgs = {
  getIdToken: async () => 'mock-jwt-token',
  councilLabel: COUNCIL_LABEL,
  request,
  onBack: () => console.log('onBack'),
  onDone: () => console.log('onDone'),
};

const RemoteStory = Template.bind({});
RemoteStory.args = { ...baseArgs, mode: 'remote' };
RemoteStory.parameters = handlers('awaiting_meeting');
RemoteStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('council.remote_title'));
  await within(canvasElement).findByText(i18n.t('council.remote_worthless_alone'));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.remote_button')));
  await within(canvasElement).findByText(i18n.t('council.handed_over_waiting', { name: request.user_name }));
};
export const ApproveRemotely = prepareStory(RemoteStory);

// In person, typing the code read on the person's screen (no camera here).
const InPersonStory = Template.bind({});
InPersonStory.args = { ...baseArgs, mode: 'in-person' };
InPersonStory.parameters = handlers('released');
InPersonStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await playFindHeading(canvasElement, i18n.t('council.in_person_title'));
  canvas.getByText(i18n.t('council.in_person_check_person'));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('device_approval.enter_code_instead')));
  const firstGroup = (await canvas.findAllByRole('textbox'))[0];
  await userEvent.click(firstGroup);
  await userEvent.paste(sampleFingerprint);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.in_person_button')));
  await canvas.findByText(i18n.t('council.handed_over_released', { name: request.user_name }));
};
export const HandOverInPerson = prepareStory(InPersonStory);

// The code is not the request's: the vault refuses to hand the share to that key.
const MismatchStory = Template.bind({});
MismatchStory.args = { ...baseArgs, mode: 'in-person' };
MismatchStory.parameters = {
  ...handlers('released'),
  encryption: {
    request: async (type: string, payload?: unknown) => {
      if (type === MSG_VAULT_COUNCIL_CONTRIBUTE) throw new VaultError(VaultErrorCode.INVALID_KEY_BINDING, 'mismatch');

      return defaultVaultRequest(type, payload);
    },
  },
};
MismatchStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('device_approval.enter_code_instead')));
  await userEvent.click((await canvas.findAllByRole('textbox'))[0]);
  await userEvent.paste(sampleFingerprint);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.in_person_button')));
  await canvas.findByText(i18n.t('council.code_mismatch'));
  expect(canvas.queryByText(i18n.t('council.handed_over_title'))).toBeNull();
};
export const WrongCode = prepareStory(MismatchStory);
