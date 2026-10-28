import { Meta, StoryFn } from '@storybook/react';
import { expect, userEvent, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import { base64ToUint8 } from '@encryption/src/crypto/encryption-backup';
import i18n from '@encryption/src/i18n';
import { MSG_VAULT_COUNCIL_CONTRIBUTE } from '@encryption/src/shared/constants';
import { DOMAIN_COUNCIL_REQUEST_FINGERPRINT } from '@encryption/src/shared/crypto-domains';
import { computeDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import {
  handleGetApiCouncilRecoveryRequestsByIdCustodian,
  handlePostApiCouncilRecoveryRequestsByIdContribute,
} from '@encryption/src/ui/api/generated/msw.gen';
import { CouncilHandOver } from '@encryption/src/ui/components/CouncilHandOver';
import { COUNCIL_LABEL } from '@encryption/src/ui/testing/council-stories';
import { sampleCouncilEscrowRecord, sampleFingerprint, samplePublicKey, sampleRosterVersion } from '@encryption/src/ui/testing/fixtures';
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

const handlers = (stage: 'collecting' | 'released') => ({
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
          chain: [sampleRosterVersion()],
          attestation: null,
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
RemoteStory.parameters = handlers('collecting');
RemoteStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('council.remote_title'));
  await within(canvasElement).findByText(i18n.t('council.remote_worthless_alone'));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.remote_button')));
  await within(canvasElement).findByText(i18n.t('council.handed_over_waiting', { name: request.user_name }));
};
export const ApproveRemotely = prepareStory(RemoteStory);

// The code the person's screen shows: the fingerprint of the request's ephemeral key.
const requestCode = () => computeDecimalFingerprint(DOMAIN_COUNCIL_REQUEST_FINGERPRINT, base64ToUint8(samplePublicKey.encryption_public_key));

async function typeCode(canvasElement: HTMLElement, code: string) {
  const canvas = within(canvasElement);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('device_approval.enter_code_instead')));
  await userEvent.click((await canvas.findAllByRole('textbox'))[0]);
  await userEvent.paste(code);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.check_code')));
}

// In person, typing the code read on the person's screen (no camera here). A
// matching code hands nothing over yet: the custodian confirms the person first.
// A threshold of 1: this share alone releases.
const InPersonStory = Template.bind({});
InPersonStory.args = { ...baseArgs, mode: 'in-person' };
InPersonStory.parameters = handlers('released');
InPersonStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await playFindHeading(canvasElement, i18n.t('council.in_person_title'));
  canvas.getByText(i18n.t('council.in_person_check_person'));
  await typeCode(canvasElement, await requestCode());
  await canvas.findByText(i18n.t('council.code_matches', { name: request.user_name }));
  const handOver = await playFindButton(canvasElement, i18n.t('council.in_person_button'));
  await expect(handOver).toBeDisabled();
  await userEvent.click(canvas.getByRole('checkbox', { name: i18n.t('council.identity_checked', { name: request.user_name }) }));
  await expect(handOver).toBeEnabled();
  await userEvent.click(handOver);
  await canvas.findByText(i18n.t('council.handed_over_released', { name: request.user_name }));
};
export const HandOverInPerson = prepareStory(InPersonStory);

// The usual case: the meeting comes first, and the other custodians approve remotely after it.
const MeetingFirstStory = Template.bind({});
MeetingFirstStory.args = { ...baseArgs, mode: 'in-person' };
MeetingFirstStory.parameters = handlers('collecting');
MeetingFirstStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await typeCode(canvasElement, await requestCode());
  await userEvent.click(await canvas.findByRole('checkbox', { name: i18n.t('council.identity_checked', { name: request.user_name }) }));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.in_person_button')));
  await canvas.findByText(i18n.t('council.handed_over_met', { name: request.user_name }));
};
export const MeetingFirst = prepareStory(MeetingFirstStory);

// The code is not the request's: refused before anything reaches the vault.
const MismatchStory = Template.bind({});
MismatchStory.args = { ...baseArgs, mode: 'in-person' };
MismatchStory.parameters = handlers('released');
MismatchStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await typeCode(canvasElement, sampleFingerprint);
  await canvas.findByText(i18n.t('council.code_mismatch'));
  expect(canvas.queryByText(i18n.t('council.code_matches', { name: request.user_name }))).toBeNull();
  expect(canvas.queryByText(i18n.t('council.handed_over_title'))).toBeNull();
};
export const WrongCode = prepareStory(MismatchStory);

// The hand-over fails once: the error shows, nothing is retried by itself, and
// the custodian can try again from the same confirmation.
let contributeCalls = 0;
const FailOnceStory = Template.bind({});
FailOnceStory.args = { ...baseArgs, mode: 'in-person' };
FailOnceStory.parameters = {
  ...handlers('released'),
  encryption: {
    request: async (type: string, payload?: unknown) => {
      if (type === MSG_VAULT_COUNCIL_CONTRIBUTE) {
        contributeCalls += 1;
        if (contributeCalls === 1) throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'integrity');
      }

      return defaultVaultRequest(type, payload);
    },
  },
};
FailOnceStory.play = async ({ canvasElement }) => {
  contributeCalls = 0;
  const canvas = within(canvasElement);
  await typeCode(canvasElement, await requestCode());
  await userEvent.click(await canvas.findByRole('checkbox', { name: i18n.t('council.identity_checked', { name: request.user_name }) }));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.in_person_button')));
  await canvas.findByText(i18n.t('errors.vault.council_integrity_failed'));
  // Still one attempt after a while: no loop.
  await new Promise((resolve) => setTimeout(resolve, 300));
  await expect(contributeCalls).toBe(1);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.in_person_button')));
  await canvas.findByText(i18n.t('council.handed_over_released', { name: request.user_name }));
  await expect(contributeCalls).toBe(2);
};
export const HandOverFailsOnce = prepareStory(FailOnceStory);
