import { Meta, StoryFn } from '@storybook/react';
import { expect, fn, userEvent, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { handleDeleteApiCouncilsEscrow, handleGetApiCouncilsForMe, handlePostApiCouncilsEscrow } from '@encryption/src/ui/api/generated/msw.gen';
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
NoneStory.parameters = { msw: { handlers: [handleGetApiCouncilsForMe({ body: { council: null, escrow: null, active_vault_created_at_millis: null, vaults: [] } })] } };
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
  await playFindHeading(canvasElement, i18n.t('council.join_title'));
  canvas.getByText(i18n.t('council.onboarding_description', members));
  // The council named once, over its members.
  expect(canvas.getAllByText(COUNCIL_LABEL)).toHaveLength(1);
  canvas.getByText('Alice Martin');
  expect(await playFindButton(canvasElement, i18n.t('council.join_button'))).toBeEnabled();
  expect(await playFindButton(canvasElement, i18n.t('council.join_verify_button'))).toBeEnabled();
  // No code to compare before joining, and no "later" outside the onboarding.
  expect(canvas.queryByLabelText(i18n.t('council.fingerprint_compared'))).toBeNull();
  expect(canvas.queryByRole('button', { name: i18n.t('council.onboarding_later') })).toBeNull();
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

// The same screen as a step of the onboarding, with "later" to skip it; joining
// hands back to the onboarding (its NewUserJoinsCouncil story).
const OnboardingStory = Template.bind({});
OnboardingStory.args = { ...baseArgs, onClose: fn(), onboarding: { onJoined: fn() } };
OnboardingStory.parameters = joining;
OnboardingStory.play = async ({ canvasElement, args }) => {
  await playFindHeading(canvasElement, i18n.t('council.join_title'));
  expect(within(canvasElement).queryByRole('button', { name: i18n.t('onboarding.btn_back') })).toBeNull();
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.onboarding_later')));
  expect(args.onClose).toHaveBeenCalled();
  expect(args.onboarding!.onJoined).not.toHaveBeenCalled();
};
export const Onboarding = prepareStory(OnboardingStory);

// Verifying by the code (the default way): confirming waits on the person
// comparing it. Stops on the ticked comparison; joining is the Accepted story.
const VerifyByCodeStory = Template.bind({});
VerifyByCodeStory.args = baseArgs;
VerifyByCodeStory.parameters = joining;
VerifyByCodeStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.join_verify_button')));
  await playFindHeading(canvasElement, i18n.t('council.verify_title'));
  canvas.getByLabelText(sampleCouncilFingerprint.match(/\d{5}/g)!.join(' '));
  // The custodians are the other way, not shown at once.
  expect(canvas.queryByText('Bruno Petit')).toBeNull();
  const confirm = await playFindButton(canvasElement, i18n.t('council.verify_code_confirm'));
  expect(confirm).toBeDisabled();
  await userEvent.click(canvas.getByLabelText(i18n.t('council.fingerprint_compared')));
  expect(confirm).toBeEnabled();
};
export const VerifyByCode = prepareStory(VerifyByCodeStory);

// Verifying through one custodian of version 1 the user knows: the names, and
// each one's code only once picked, in a dialog.
const VerifyByCustodianStory = Template.bind({});
VerifyByCustodianStory.args = baseArgs;
VerifyByCustodianStory.parameters = joining;
VerifyByCustodianStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.join_verify_button')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.verify_with_person')));
  await canvas.findByText(i18n.t('council.verify_person_hint'));
  const compare = await canvas.findAllByRole('button', { name: i18n.t('council.verify_person_compare') });
  expect(compare).toHaveLength(sampleRosterVersion().members.length);
  expect(canvas.queryByLabelText(sampleCouncilFingerprint.match(/\d{5}/g)!.join(' '))).toBeNull();
  await userEvent.click(compare[0]);
  const dialog = within(await within(document.body).findByRole('dialog'));
  await dialog.findByRole('button', { name: i18n.t('council.verify_person_button') });
};
export const VerifyByCustodian = prepareStory(VerifyByCustodianStory);

const EnrolledStory = Template.bind({});
EnrolledStory.args = baseArgs;
EnrolledStory.parameters = { msw: { handlers: [handleGetApiCouncilsForMe({ body: forMe({ escrow: {} }) })] } };
EnrolledStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.enrolled_description', members));
  // Joined without verifying: said, with the way to verify now.
  canvas.getByText(i18n.t('council.enrolled_unverified'));
  canvas.getByText(i18n.t('council.chip_unverified'));
  await playFindButton(canvasElement, i18n.t('council.verify_open'));
};
export const Enrolled = prepareStory(EnrolledStory);

// Leaving is signed by the vault and explained first: the council could no
// longer help, and joining again stays possible.
const LeaveStory = Template.bind({});
LeaveStory.args = baseArgs;
LeaveStory.parameters = EnrolledStory.parameters;
LeaveStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.leave')));
  const dialog = within(await within(document.body).findByRole('dialog'));
  await dialog.findByText(i18n.t('council.leave_body'));
  dialog.getByText(i18n.t('council.leave_again'));
  await dialog.findByRole('button', { name: i18n.t('council.leave_confirm') });
};
export const LeaveCouncil = prepareStory(LeaveStory);

// Leaving also takes a fresh second factor: the dialog stays open on the way to
// confirm it, and leaving is clicked again afterwards.
const LeaveStepUpStory = Template.bind({});
LeaveStepUpStory.args = { ...baseArgs, onStepUp: fn() };
LeaveStepUpStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilsForMe({ body: forMe({ escrow: {} }) }),
      handleDeleteApiCouncilsEscrow(
        () =>
          new Response(JSON.stringify({ code: 'insufficient_user_authentication', params: { max_age: 300 } }), {
            status: 401,
            headers: {
              'content-type': 'application/json',
              'www-authenticate': 'Bearer error="insufficient_user_authentication", max_age="300"',
            },
          })
      ),
    ],
  },
};
LeaveStepUpStory.play = async ({ args, canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.leave')));
  const dialog = within(await within(document.body).findByRole('dialog'));
  await userEvent.click(await dialog.findByRole('button', { name: i18n.t('council.leave_confirm') }));
  await dialog.findByText(i18n.t('council.step_up_required'));
  await userEvent.click(dialog.getByRole('button', { name: i18n.t('auth.step_up_confirm') }));
  expect(args.onStepUp).toHaveBeenCalledOnce();
};
export const LeaveNeedsStepUp = prepareStory(LeaveStepUpStory);

const EnrolledVerifiedStory = Template.bind({});
EnrolledVerifiedStory.args = baseArgs;
EnrolledVerifiedStory.parameters = {
  msw: { handlers: [handleGetApiCouncilsForMe({ body: forMe({ escrow: {} }) })] },
  encryption: { request: vaultCheckingEscrow('ok', true) },
};
EnrolledVerifiedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.chip_protected'));
  // Verified: no code left to show.
  expect(canvas.queryByLabelText(sampleCouncilFingerprint.match(/\d{5}/g)!.join(' '))).toBeNull();
  expect(canvas.queryByText(i18n.t('council.enrolled_unverified'))).toBeNull();
  expect(canvas.queryByRole('button', { name: i18n.t('council.verify_open') })).toBeNull();
};
export const EnrolledVerified = prepareStory(EnrolledVerifiedStory);

// Opened by the settings' "verify my council": straight to the checks.
const StartVerifyingStory = Template.bind({});
StartVerifyingStory.args = { ...baseArgs, startVerifying: true };
StartVerifyingStory.parameters = EnrolledStory.parameters;
StartVerifyingStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('council.verify_title'));
  await within(canvasElement).findByText(i18n.t('council.fingerprint_hint'));
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
  within(canvasElement).getByText(i18n.t('council.again_explanation'));
  expect(await playFindButton(canvasElement, i18n.t('council.again_button'))).toBeEnabled();
  // Set up again as it was: no verification offered here.
  expect(within(canvasElement).queryByRole('button', { name: i18n.t('council.join_verify_button') })).toBeNull();
};
export const SetUpAgain = prepareStory(SetUpAgainStory);
