import { Meta, StoryFn } from '@storybook/react';
import { expect, userEvent, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { handleGetApiCouncilsForMe, handlePostApiCouncilsEscrow } from '@encryption/src/ui/api/generated/msw.gen';
import { RecoveryCouncil } from '@encryption/src/ui/components/RecoveryCouncil';
import { COUNCIL_LABEL, forMe, vaultCheckingEscrow } from '@encryption/src/ui/testing/council-stories';
import { sampleCouncilFingerprint, sampleRosterVersion } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof RecoveryCouncil;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Modals/RecoveryCouncil',
  component: RecoveryCouncil,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: 'medium',
      docs: {
        description: {
          component:
            "The user's side of their organization's recovery council: joining it, at once or after verifying it (by its code or through a custodian the user knows), then its state. Opened from the encryption settings, or as the `recovery-council` settings section.",
        },
      },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <RecoveryCouncil {...args} />;
const baseArgs = { getIdToken: async () => 'mock-jwt-token', onClose: () => console.log('onClose') };
const members = { threshold: 2, count: 4 };

const NoneStory = Template.bind({});
NoneStory.args = baseArgs;
NoneStory.parameters = { msw: { handlers: [handleGetApiCouncilsForMe({ body: { council: null, escrow: null } })] } };
NoneStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.none'));
};
export const NoCouncil = prepareStory(NoneStory);

// First time: the names, the threshold, and two ways in. Joining at once asks
// for no comparison; joining and verifying opens the two checks.
const joining = {
  msw: {
    handlers: [handleGetApiCouncilsForMe({ body: forMe() }), handlePostApiCouncilsEscrow({ body: { id: '7f1c2b3a-0000-4000-8000-000000000001' } })],
  },
};

const AcceptStory = Template.bind({});
AcceptStory.args = baseArgs;
AcceptStory.parameters = joining;
AcceptStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await playFindHeading(canvasElement, i18n.t('council.accept_title', { council: COUNCIL_LABEL }));
  canvas.getByText('Alice Martin');
  canvas.getByText(i18n.t('council.members', members));
  canvas.getByText(i18n.t('council.join_later_hint'));
  expect(await playFindButton(canvasElement, i18n.t('council.join_button'))).toBeEnabled();
  expect(await playFindButton(canvasElement, i18n.t('council.join_verify_button'))).toBeEnabled();
  // No code to compare before joining.
  expect(canvas.queryByLabelText(i18n.t('council.fingerprint_compared'))).toBeNull();
};
export const Accept = prepareStory(AcceptStory);

const AcceptedStory = Template.bind({});
AcceptedStory.args = baseArgs;
AcceptedStory.parameters = joining;
AcceptedStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.join_button')));
  await playFindHeading(canvasElement, i18n.t('council.done_title'));
};
export const Accepted = prepareStory(AcceptedStory);

// Verifying by the code: confirming waits on the person comparing it.
const VerifyByCodeStory = Template.bind({});
VerifyByCodeStory.args = baseArgs;
VerifyByCodeStory.parameters = joining;
VerifyByCodeStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.join_verify_button')));
  await playFindHeading(canvasElement, i18n.t('council.verify_title', { council: COUNCIL_LABEL }));
  canvas.getByLabelText(sampleCouncilFingerprint.match(/\d{5}/g)!.join(' '));
  const confirm = await playFindButton(canvasElement, i18n.t('council.verify_code_confirm'));
  expect(confirm).toBeDisabled();
  await userEvent.click(canvas.getByLabelText(i18n.t('council.fingerprint_compared')));
  expect(confirm).toBeEnabled();
  await userEvent.click(confirm);
  await playFindHeading(canvasElement, i18n.t('council.done_title'));
};
export const VerifyByCode = prepareStory(VerifyByCodeStory);

// Verifying through one custodian of version 1 the user knows: their own code.
const VerifyByCustodianStory = Template.bind({});
VerifyByCustodianStory.args = baseArgs;
VerifyByCustodianStory.parameters = joining;
VerifyByCustodianStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.join_verify_button')));
  await canvas.findByText(i18n.t('council.verify_person_title'));
  canvas.getByText(i18n.t('council.verify_person_hint'));
  // One card per member of version 1, each with its own check.
  const checks = await canvas.findAllByRole('button', { name: i18n.t('council.verify_person_button') });
  expect(checks).toHaveLength(sampleRosterVersion().members.length);
  await userEvent.click(checks[0]);
  await playFindHeading(canvasElement, i18n.t('council.done_title'));
};
export const VerifyByCustodian = prepareStory(VerifyByCustodianStory);

const EnrolledStory = Template.bind({});
EnrolledStory.args = baseArgs;
EnrolledStory.parameters = { msw: { handlers: [handleGetApiCouncilsForMe({ body: forMe({ escrow: {} }) })] } };
EnrolledStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.enrolled_description', { council: COUNCIL_LABEL, ...members }));
  canvas.getByText(i18n.t('council.chip_protected'));
  // Joined without verifying: said, with the way to verify now.
  canvas.getByText(i18n.t('council.enrolled_unverified'));
  canvas.getByText(i18n.t('council.chip_unverified'));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.verify_open')));
  await playFindHeading(canvasElement, i18n.t('council.verify_title', { council: COUNCIL_LABEL }));
};
export const Enrolled = prepareStory(EnrolledStory);

const EnrolledVerifiedStory = Template.bind({});
EnrolledVerifiedStory.args = baseArgs;
EnrolledVerifiedStory.parameters = {
  msw: { handlers: [handleGetApiCouncilsForMe({ body: forMe({ escrow: {} }) })] },
  encryption: { request: vaultCheckingEscrow('ok', true) },
};
EnrolledVerifiedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.chip_verified'));
  canvas.getByLabelText(sampleCouncilFingerprint.match(/\d{5}/g)!.join(' '));
  expect(canvas.queryByText(i18n.t('council.enrolled_unverified'))).toBeNull();
  expect(canvas.queryByRole('button', { name: i18n.t('council.verify_open') })).toBeNull();
};
export const EnrolledVerified = prepareStory(EnrolledVerifiedStory);

// Opened by the settings' "verify my council": straight to the checks.
const StartVerifyingStory = Template.bind({});
StartVerifyingStory.args = { ...baseArgs, startVerifying: true };
StartVerifyingStory.parameters = EnrolledStory.parameters;
StartVerifyingStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('council.verify_title', { council: COUNCIL_LABEL }));
  await within(canvasElement).findByText(i18n.t('council.verify_code_title'));
};
export const StartVerifying = prepareStory(StartVerifyingStory);

// Two custodians left: one more departure and the council could no longer help.
const AtRiskStory = Template.bind({});
AtRiskStory.args = baseArgs;
AtRiskStory.parameters = {
  msw: {
    handlers: [handleGetApiCouncilsForMe({ body: forMe({ escrow: { health: { live: 2, threshold: 2, status: 'at-risk', outdated: true } } }) })],
  },
};
AtRiskStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.at_risk'));
  canvas.getByText(i18n.t('council.outdated'));
  expect(canvas.queryByText(i18n.t('council.chip_protected'))).toBeNull();
};
export const AtRisk = prepareStory(AtRiskStory);

// The configuration dropped the council: nothing changes for the user.
const NotConfiguredStory = Template.bind({});
NotConfiguredStory.args = baseArgs;
NotConfiguredStory.parameters = { msw: { handlers: [handleGetApiCouncilsForMe({ body: forMe({ escrow: {}, configured: false }) })] } };
NotConfiguredStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.not_configured_user'));
};
export const NotConfigured = prepareStory(NotConfiguredStory);

const TamperedStory = Template.bind({});
TamperedStory.args = baseArgs;
TamperedStory.parameters = {
  msw: { handlers: [handleGetApiCouncilsForMe({ body: forMe({ escrow: {} }) })] },
  encryption: { request: vaultCheckingEscrow('chain-broken') },
};
TamperedStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.check_chain_broken'));
};
export const MembershipNotVerified = prepareStory(TamperedStory);

// Too few custodians can still open the setup: an explicit new setup, never automatic.
const SetUpAgainStory = Template.bind({});
SetUpAgainStory.args = baseArgs;
SetUpAgainStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilsForMe({ body: forMe({ escrow: { health: { live: 1, threshold: 2, status: 'lost', outdated: true } } }) }),
      handlePostApiCouncilsEscrow({ body: { id: '7f1c2b3a-0000-4000-8000-000000000002' } }),
    ],
  },
};
SetUpAgainStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('council.again_title'));
  const button = await playFindButton(canvasElement, i18n.t('council.again_button'));
  expect(button).toBeEnabled();
  await userEvent.click(button);
  await playFindHeading(canvasElement, i18n.t('council.done_title'));
};
export const SetUpAgain = prepareStory(SetUpAgainStory);
