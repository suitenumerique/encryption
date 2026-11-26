import { Meta, StoryFn } from '@storybook/react';
import { HttpResponse } from 'msw';
import { expect, fn, userEvent, waitFor, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { MSG_VAULT_COUNCIL_CHECK_SHARES, MSG_VAULT_COUNCIL_RESHARE_BATCH } from '@encryption/src/shared/constants';
import type { CouncilCheckResultsBody } from '@encryption/src/shared/schemas/recovery-council';
import type { CouncilRequestSummary, CouncilsMine } from '@encryption/src/ui/api/council-client';
import {
  handleGetApiCouncilsByCouncilIdSharesToCheck,
  handleGetApiCouncilsMine,
  handleGetApiCouncilsReshareBySessionIdBatch,
  handlePostApiCouncilRecoveryRequestsByIdAbort,
  handlePostApiCouncilsByCouncilIdSharesChecked,
  handlePostApiCouncilsReshareBySessionIdSubShares,
} from '@encryption/src/ui/api/generated/msw.gen';
import { CouncilCustodian } from '@encryption/src/ui/components/CouncilCustodian';
import { COUNCIL_LABEL, councilRequestsHandler, custodianCouncil, requestCounts } from '@encryption/src/ui/testing/council-stories';
import { sampleCouncilEscrowRecord, sampleCouncilFingerprint, sampleCouncilMembers, sampleRosterVersion } from '@encryption/src/ui/testing/fixtures';
import { defaultVaultRequest } from '@encryption/src/ui/testing/mock-encryption';

type ComponentType = typeof CouncilCustodian;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

const NOW = Date.UTC(2026, 9, 28, 9);
const DAY = 24 * 60 * 60 * 1000;

export default {
  title: 'Preview/Modals/CouncilCustodian',
  component: CouncilCustodian,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: true,
      date: new Date(NOW),
      docs: {
        description: {
          component:
            'The custodian space: the recovery councils the user sits in or is invited to, those with something waiting first, each on a page of its own with what waits on them (a change to sign, requests to approve or hand over in person, setups to move after a membership change). With a single council its page opens at once. Opened from the encryption settings, only for a custodian or an invitee.',
        },
      },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <CouncilCustodian {...args} />;
const baseArgs = { getIdToken: async () => 'mock-jwt-token', userId: sampleCouncilMembers[0].user_id };

/** `/api/councils/mine` answering `councils`, and their request list answering `requests`. */
function mine(councils: CouncilsMine['councils'], mfa = true, requests: CouncilRequestSummary[] = []) {
  return { msw: { handlers: [handleGetApiCouncilsMine({ body: { mfa_enforced: mfa, councils } }), councilRequestsHandler(requests)] } };
}

const request = {
  id: '5d6e7f80-0000-4000-8000-000000000001',
  user_name: 'Ursula Roux',
  user_email: 'ursula.roux@numerique.gouv.fr',
  created_at_millis: NOW - DAY,
  expires_at_millis: NOW + 6 * DAY,
  stage: 'collecting' as const,
  contributors: [],
  threshold: 2,
  my_contribution: 'none' as const,
  can_contribute: true,
  holds_part: true,
};

const EmptyStory = Template.bind({});
EmptyStory.args = baseArgs;
EmptyStory.parameters = mine([]);
// Never reached from the settings (no row without a council): only a link opened by hand.
EmptyStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.custodian_none'));
  // Closed by the modal's own control, as every page of the space.
  expect(within(canvasElement).queryByRole('button', { name: i18n.t('settings.done') })).toBeNull();
};
export const NotACustodian = prepareStory(EmptyStory);

// The space could not be loaded: an error to retry, never "not a member".
const LoadFailedStory = Template.bind({});
LoadFailedStory.args = baseArgs;
LoadFailedStory.parameters = {
  msw: { handlers: [handleGetApiCouncilsMine(() => Response.json({ code: 'internal_error', message: 'Internal error' }, { status: 500 }))] },
};
LoadFailedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.custodian_load_failed'));
  expect(canvas.queryByText(i18n.t('council.custodian_none'))).toBeNull();
  await playFindButton(canvasElement, i18n.t('council.retry'));
};
export const LoadFailed = prepareStory(LoadFailedStory);

// In force: the council's code, the one the organization publishes once. Rarely
// needed, so behind a small button.
const CodeStory = Template.bind({});
CodeStory.args = baseArgs;
CodeStory.parameters = mine([custodianCouncil()]);
CodeStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  // A single council opens on its own page, named in the title.
  await playFindHeading(canvasElement, COUNCIL_LABEL);
  expect(canvas.queryByText(i18n.t('council.custodian_code_hint'))).toBeNull();
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.fingerprint_title')));
  const dialog = within(await within(document.body).findByRole('dialog'));
  await dialog.findByText(i18n.t('council.custodian_code_hint'));
  dialog.getByLabelText(sampleCouncilFingerprint.match(/\d{5}/g)!.join(' '));
  dialog.getByRole('button', { name: i18n.t('council.copy_code') });
};
export const CouncilCode = prepareStory(CodeStory);

// Who else sits in the council: the version in force, the custodian first.
const MembersStory = Template.bind({});
MembersStory.args = baseArgs;
MembersStory.parameters = mine([custodianCouncil()]);
MembersStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.custodians_line', { count: 2, total: 4 }));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.members_button')));
  const dialog = within(await within(document.body).findByRole('dialog'));
  const names = [...(await dialog.findAllByText(/^(Alice Martin|Bruno Petit|Chloé Durand|David Moreau)$/))].map((n) => n.textContent);
  expect(names[0]).toBe('Alice Martin');
  expect(names).toHaveLength(4);
  dialog.getByText(i18n.t('council.change_me'));
};
export const Custodians = prepareStory(MembersStory);

// Named in the configuration, the council not in force yet: accept the role.
const InvitedStory = Template.bind({});
InvitedStory.args = baseArgs;
InvitedStory.parameters = mine([
  custodianCouncil({
    role: 'invited',
    my_slot: null,
    chain: [],
    health: { escrows: 0, ok: 0, at_risk: 0, lost: 0, lost_names: [], outdated: [], absent: [], absence_days: 90, team_ready: true },
    proposal: {
      roster: sampleRosterVersion({ signatures: [] }),
      quorum_missing: 0,
      pending_members: [],
      escrows_lost: 0,
      signed_by_me: false,
      may_sign: true,
    },
  }),
]);
InvitedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.invitation_title'));
  // Maybe the first time they hear of a council: what it is, in one sentence.
  canvas.getByText(i18n.t('council.invitation_intro'));
  await playFindButton(canvasElement, i18n.t('council.review_and_accept'));
  // No code before version 1 is signed.
  expect(canvas.queryByText(i18n.t('council.custodian_code_hint'))).toBeNull();
  // An invitee sees no request and no health: those are custodians' business.
  expect(canvas.queryByText(i18n.t('council.requests_title_count', { count: 0 }))).toBeNull();
};
export const Invited = prepareStory(InvitedStory);

// Accepted, the others not yet: said as done, with what the missing acceptances are for.
const InvitedSignedStory = Template.bind({});
InvitedSignedStory.args = baseArgs;
InvitedSignedStory.parameters = mine([
  custodianCouncil({
    role: 'invited',
    my_slot: null,
    chain: [],
    health: { escrows: 0, ok: 0, at_risk: 0, lost: 0, lost_names: [], outdated: [], absent: [], absence_days: 90, team_ready: true },
    proposal: {
      roster: sampleRosterVersion({ signatures: [] }),
      quorum_missing: 0,
      pending_members: [
        { slot: 2, name: 'Bob Dupont' },
        { slot: 3, name: 'Charlie Leroy' },
      ],
      escrows_lost: 0,
      signed_by_me: true,
      may_sign: true,
    },
  }),
]);
InvitedSignedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.invitation_signed_title'));
  const names = new Intl.ListFormat(i18n.language, { type: 'conjunction' }).format(['Bob Dupont', 'Charlie Leroy']);
  canvas.getByText(i18n.t('council.invitation_signed', { count: 2, names }));
  expect(canvas.queryByText(i18n.t('council.invitation_title'))).toBeNull();
  expect(canvas.queryByRole('button', { name: i18n.t('council.review_and_accept') })).toBeNull();
};
export const InvitedSigned = prepareStory(InvitedSignedStory);

// Two requests: Ursula already met a custodian (remote approval is open), Victor
// met nobody yet (only a share in person, after checking the code).
const RequestsStory = Template.bind({});
RequestsStory.args = baseArgs;
const twoRequests: CouncilRequestSummary[] = [
  { ...request, contributors: [{ slot: 2, name: 'Bruno Petit', in_person: true }] },
  {
    ...request,
    id: '5d6e7f80-0000-4000-8000-000000000002',
    user_name: 'Victor Lemaire',
    user_email: 'victor.lemaire@numerique.gouv.fr',
    stage: 'awaiting_meeting',
  },
];
RequestsStory.parameters = mine([custodianCouncil(requestCounts(twoRequests))], true, twoRequests);
RequestsStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText('Ursula Roux');
  canvas.getByText(i18n.t('council.stage_awaiting_meeting'));
  // Each row's band says what it asks of this custodian, with its one action.
  canvas.getByText(i18n.t('council.request_nobody_met'));
  canvas.getByText(
    [i18n.t('council.request_met_by', { names: 'Bruno Petit' }), i18n.t('council.request_parts', { count: 1, threshold: 2 })].join(' · ')
  );
  // One way each: in person before the meeting, remotely after it.
  expect(canvas.getAllByRole('button', { name: i18n.t('council.approve_remotely') })).toHaveLength(1);
  expect(canvas.getAllByRole('button', { name: i18n.t('council.hand_over_in_person') })).toHaveLength(1);
};
export const Requests = prepareStory(RequestsStory);

// This custodian met the person: said once, without their own name in the progress.
const MetByMeStory = Template.bind({});
MetByMeStory.args = baseArgs;
const metByMe: CouncilRequestSummary[] = [
  { ...request, contributors: [{ slot: 1, name: 'Alice Martin', in_person: true }], my_contribution: 'in_person', can_contribute: false },
];
MetByMeStory.parameters = mine([custodianCouncil(requestCounts(metByMe))], true, metByMe);
MetByMeStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(`${i18n.t('council.my_contribution_in_person')} ${i18n.t('council.request_parts', { count: 1, threshold: 2 })}`);
  expect(canvas.queryByText(new RegExp(i18n.t('council.request_met_by', { names: 'Alice Martin' })))).toBeNull();
};
export const MetByMe = prepareStory(MetByMeStory);

const StopRequestStory = Template.bind({});
StopRequestStory.args = baseArgs;
StopRequestStory.parameters = mine([custodianCouncil(requestCounts([request]))], true, [request]);
// Out of the usual path: in the request's "⋯" menu, then confirmed in a dialog.
StopRequestStory.play = async ({ canvasElement }) => {
  const body = within(document.body);
  expect(within(canvasElement).queryByRole('button', { name: i18n.t('council.abort') })).toBeNull();
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.request_menu', { name: 'Ursula Roux' })));
  await userEvent.click(await body.findByRole('menuitem', { name: i18n.t('council.abort') }));
  await playFindHeading(document.body, i18n.t('council.abort_title', { name: 'Ursula Roux' }));
  await body.findByRole('button', { name: i18n.t('council.abort_confirm') });
};
export const StopRequestConfirmation = prepareStory(StopRequestStory);

// Stopping takes a fresh second factor: asked in the confirmation itself, not on the page behind it.
const StopRequestStepUpStory = Template.bind({});
StopRequestStepUpStory.args = { ...baseArgs, onStepUp: fn() };
StopRequestStepUpStory.parameters = {
  msw: {
    handlers: [
      ...mine([custodianCouncil(requestCounts([request]))], true, [request]).msw.handlers,
      handlePostApiCouncilRecoveryRequestsByIdAbort(
        () =>
          new Response(JSON.stringify({ code: 'insufficient_user_authentication', params: { max_age: 300 } }), {
            status: 401,
            headers: { 'content-type': 'application/json', 'www-authenticate': 'Bearer error="insufficient_user_authentication", max_age="300"' },
          })
      ),
    ],
  },
};
StopRequestStepUpStory.play = async ({ args, canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.request_menu', { name: 'Ursula Roux' })));
  await userEvent.click(await within(document.body).findByRole('menuitem', { name: i18n.t('council.abort') }));
  const dialog = within(await within(document.body).findByRole('dialog', { name: i18n.t('council.abort') }));
  await userEvent.click(await dialog.findByRole('button', { name: i18n.t('council.abort_confirm') }));
  await dialog.findByText(i18n.t('council.step_up_required'));
  await userEvent.click(dialog.getByRole('button', { name: i18n.t('auth.step_up_confirm') }));
  expect(args.onStepUp).toHaveBeenCalledOnce();
};
export const StopRequestNeedsStepUp = prepareStory(StopRequestStepUpStory);

// The confirmation tab came back signed in as someone else: the notice says so instead of asking the same again.
const StepUpWrongUserStory = Template.bind({});
StepUpWrongUserStory.args = { ...baseArgs, onStepUp: fn(), wrongUser: true };
StepUpWrongUserStory.parameters = StopRequestStepUpStory.parameters;
StepUpWrongUserStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.request_menu', { name: 'Ursula Roux' })));
  await userEvent.click(await within(document.body).findByRole('menuitem', { name: i18n.t('council.abort') }));
  const dialog = within(await within(document.body).findByRole('dialog', { name: i18n.t('council.abort') }));
  await userEvent.click(await dialog.findByRole('button', { name: i18n.t('council.abort_confirm') }));
  await dialog.findByText(i18n.t('auth.step_up_wrong_user'));
  expect(dialog.queryByText(i18n.t('council.step_up_required'))).toBeNull();
};
export const StepUpWrongUser = prepareStory(StepUpWrongUserStory);

// A change of membership waiting for this custodian's signature.
const ChangeToSignStory = Template.bind({});
ChangeToSignStory.args = baseArgs;
ChangeToSignStory.parameters = mine([
  custodianCouncil({
    proposal: {
      roster: sampleRosterVersion({
        version: 2,
        previous_roster_hash: 'AAAA',
        members: [
          ...sampleCouncilMembers.slice(0, 3),
          { slot: 5, user_id: 'aaaaaaaa-0000-4000-8000-000000000005', identity_public_key: 'BBBB', name: 'Élise Garnier' },
        ],
        signatures: [],
      }),
      quorum_missing: 2,
      pending_members: [{ slot: 5, name: 'Élise Garnier' }],
      escrows_lost: 0,
      signed_by_me: false,
      may_sign: true,
    },
  }),
]);
ChangeToSignStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.proposal_title', { version: 2 }));
  await playFindButton(canvasElement, i18n.t('council.review_and_sign'));
};
export const ChangeToSign = prepareStory(ChangeToSignStory);

// A three-member team adding Élise: who the change still waits for, from both sides of it.
const threeMembers = sampleCouncilMembers.slice(0, 3).map((m, i) => ({ ...m, identity_public_key: `KEY${i}` }));
const elise = { slot: 5, user_id: 'aaaaaaaa-0000-4000-8000-000000000005', identity_public_key: 'KEY5', name: 'Élise Garnier' };
const addingElise = (signedBy: string[]) =>
  custodianCouncil({
    chain: [sampleRosterVersion({ members: threeMembers })],
    proposal: {
      roster: sampleRosterVersion({
        version: 2,
        previous_roster_hash: 'AAAA',
        members: [...threeMembers, elise],
        signatures: signedBy.map((key) => ({ identity_public_key: key, signature: 'SIG' })),
      }),
      quorum_missing: 2 - signedBy.filter((key) => key !== 'KEY5').length,
      pending_members: signedBy.includes('KEY5') ? [] : [{ slot: 5, name: 'Élise Garnier' }],
      escrows_lost: 0,
      signed_by_me: true,
      may_sign: false,
    },
  });

const SignedWaitingStory = Template.bind({});
SignedWaitingStory.args = baseArgs;
SignedWaitingStory.parameters = mine([addingElise(['KEY0'])]);
SignedWaitingStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  // What was confirmed, for whoever comes back days later, then who it waits for.
  await canvas.findByText(i18n.t('council.change_joining', { names: 'Élise Garnier' }));
  canvas.getByText(i18n.t('council.proposal_to_accept', { names: 'Élise Garnier' }));
  const or = new Intl.ListFormat(i18n.language, { type: 'disjunction' }).format(['Bruno Petit', 'Chloé Durand']);
  canvas.getByText(i18n.t('council.proposal_to_confirm_some', { count: 1, names: or }));
};
export const SignedWaitingForOthers = prepareStory(SignedWaitingStory);

// Chloé started over and comes back under a new identity: she accepts as a
// newcomer, and the identity she left is not counted among those who confirm.
const fourMembers = sampleCouncilMembers.map((m, i) => ({ ...m, identity_public_key: `KEY${i}` }));
const ChloeBackStory = Template.bind({});
ChloeBackStory.args = { ...baseArgs, userId: fourMembers[1].user_id };
ChloeBackStory.parameters = mine([
  custodianCouncil({
    chain: [sampleRosterVersion({ members: fourMembers })],
    proposal: {
      roster: sampleRosterVersion({
        version: 2,
        previous_roster_hash: 'AAAA',
        members: fourMembers.map((m) => (m.slot === 3 ? { ...m, identity_public_key: 'KEY2B' } : m)),
        signatures: [{ identity_public_key: 'KEY1', signature: 'SIG' }],
      }),
      quorum_missing: 2,
      pending_members: [{ slot: 3, name: 'Chloé Durand' }],
      escrows_lost: 0,
      signed_by_me: true,
      may_sign: false,
    },
  }),
]);
ChloeBackStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.change_new_keys', { names: 'Chloé Durand' }));
  canvas.getByText(i18n.t('council.proposal_to_accept', { names: 'Chloé Durand' }));
  const and = new Intl.ListFormat(i18n.language, { type: 'conjunction' }).format(['Alice Martin', 'David Moreau']);
  canvas.getByText(i18n.t('council.proposal_to_confirm', { names: and }));
};
export const SignedMemberBack = prepareStory(ChloeBackStory);

// Chloé's own side: her return, hers to accept, not a change about someone else.
const MyReturnStory = Template.bind({});
MyReturnStory.args = { ...baseArgs, userId: fourMembers[2].user_id };
MyReturnStory.parameters = mine([
  custodianCouncil({
    chain: [sampleRosterVersion({ members: fourMembers })],
    proposal: {
      roster: sampleRosterVersion({
        version: 2,
        previous_roster_hash: 'AAAA',
        members: fourMembers.map((m) => (m.slot === 3 ? { ...m, identity_public_key: 'KEY2B' } : m)),
        signatures: [{ identity_public_key: 'KEY1', signature: 'SIG' }],
      }),
      quorum_missing: 2,
      pending_members: [{ slot: 3, name: 'Chloé Durand' }],
      escrows_lost: 0,
      signed_by_me: false,
      may_sign: true,
    },
  }),
]);
MyReturnStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.return_title'));
  canvas.getByText(i18n.t('council.return_description'));
  await playFindButton(canvasElement, i18n.t('council.review_and_accept'));
  expect(canvas.queryByText(i18n.t('council.change_new_keys', { names: 'Chloé Durand' }))).toBeNull();
};
export const MyReturnToAccept = prepareStory(MyReturnStory);

// Chloé is among those the change removes: she reads it about herself, not as a name in the list.
const MyDepartureStory = Template.bind({});
MyDepartureStory.args = { ...baseArgs, userId: fourMembers[2].user_id };
MyDepartureStory.parameters = mine([
  custodianCouncil({
    chain: [sampleRosterVersion({ members: fourMembers })],
    proposal: {
      roster: sampleRosterVersion({ version: 2, previous_roster_hash: 'AAAA', threshold: 1, members: fourMembers.slice(0, 2), signatures: [] }),
      quorum_missing: 3,
      pending_members: [],
      escrows_lost: 0,
      signed_by_me: false,
      may_sign: true,
    },
  }),
]);
MyDepartureStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.leave_title'));
  // The rest of the change stays in view: who else leaves, and the new threshold.
  const changes = [i18n.t('council.change_leaving', { names: 'David Moreau' }), i18n.t('council.change_threshold', { before: 2, count: 1 })];
  canvas.getByText(i18n.t('council.leave_description'));
  canvas.getByText(i18n.t('council.leave_also'));
  for (const line of changes) canvas.getByText(line);
  await playFindButton(canvasElement, i18n.t('council.review_and_sign'));
};
export const MyDeparture = prepareStory(MyDepartureStory);

// Élise's side: named by a change to a team already in force, an invitation for her.
const JoiningStory = Template.bind({});
JoiningStory.args = { ...baseArgs, userId: elise.user_id };
JoiningStory.parameters = mine([
  { ...addingElise(['KEY0']), role: 'invited', my_slot: null, proposal: { ...addingElise(['KEY0']).proposal!, signed_by_me: false, may_sign: true } },
]);
JoiningStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.invitation_title'));
  canvas.getByText(i18n.t('council.invitation_join_description', { threshold: 2, count: 4 }));
  await playFindButton(canvasElement, i18n.t('council.review_and_accept'));
  expect(canvas.queryByText(i18n.t('council.change_joining', { names: 'Élise Garnier' }))).toBeNull();
};
export const JoiningAnExistingTeam = prepareStory(JoiningStory);

// After a departure: setups still split over the old version, to move.
const OutdatedStory = Template.bind({});
OutdatedStory.args = baseArgs;
OutdatedStory.parameters = mine([
  custodianCouncil({
    chain: [sampleRosterVersion(), sampleRosterVersion({ version: 2, members: sampleCouncilMembers.slice(0, 3) })],
    health: {
      escrows: 128,
      ok: 40,
      at_risk: 88,
      lost: 0,
      lost_names: [],
      outdated: [{ version: 1, escrows: 88 }],
      absent: [],
      absence_days: 90,
      team_ready: true,
    },
  }),
]);
OutdatedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.outdated_title', { count: 88 }));
  canvas.getByText(i18n.t('council.outdated_description'));
  // The move is the remedy: no separate explanation of the risk.
  expect(canvas.queryByText(i18n.t('council.health_at_risk_explained', { count: 88 }))).toBeNull();
  canvas.getByText(i18n.t('council.health_at_risk', { count: 88 }));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.reshare_button')));
  await playFindHeading(canvasElement, i18n.t('council.reshare_title'));
  // Exactly the source threshold, the custodian first.
  expect(canvas.getByLabelText(i18n.t('council.reshare_me', { name: 'Alice Martin' }))).toBeChecked();
  await playFindButton(canvasElement, i18n.t('council.reshare_start'));
};
export const MoveSetups = prepareStory(OutdatedStory);

// Only a member added: the setups stay as safe, and the newcomer holds no part of them, nor of their requests, until the move.
const AddedOnlyStory = Template.bind({});
AddedOnlyStory.args = { ...baseArgs, userId: elise.user_id };
const beforeMove: CouncilRequestSummary[] = [{ ...request, stage: 'awaiting_meeting', can_contribute: false, holds_part: false }];
AddedOnlyStory.parameters = mine(
  [
    custodianCouncil({
      chain: [sampleRosterVersion({ members: threeMembers }), sampleRosterVersion({ version: 2, members: [...threeMembers, elise] })],
      my_slot: 5,
      health: {
        escrows: 2,
        ok: 2,
        at_risk: 0,
        lost: 0,
        lost_names: [],
        outdated: [{ version: 1, escrows: 2 }],
        absent: [],
        absence_days: 90,
        team_ready: true,
      },
      ...requestCounts(beforeMove),
    }),
  ],
  true,
  beforeMove
);
AddedOnlyStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.outdated_added'));
  expect(canvas.queryByText(i18n.t('council.outdated_description'))).toBeNull();
  // Recoverable, but not done until moved: no green "all recoverable".
  canvas.getByText(i18n.t('council.health_to_move'));
  expect(canvas.queryByText(i18n.t('council.health_ok'))).toBeNull();
  await canvas.findByText(i18n.t('council.request_no_part'));
};
export const SetupsToMoveAfterAnAddition = prepareStory(AddedOnlyStory);

// A helper's part of a resharing, not processed yet.
const runningCouncil = custodianCouncil({
  chain: [sampleRosterVersion(), sampleRosterVersion({ version: 2 })],
  health: {
    escrows: 128,
    ok: 40,
    at_risk: 88,
    lost: 0,
    lost_names: [],
    outdated: [{ version: 1, escrows: 88 }],
    absent: [],
    absence_days: 90,
    team_ready: true,
  },
  reshare: {
    session_id: '0c0c0c0c-0000-4000-8000-000000000001',
    source_version: 1,
    target_version: 2,
    helper_slots: [1, 2],
    i_am_helper: true,
    remaining_for_me: 88,
    remaining: 88,
  },
});

const ReshareRunningStory = Template.bind({});
ReshareRunningStory.args = baseArgs;
ReshareRunningStory.parameters = mine([runningCouncil]);
ReshareRunningStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  // This custodian's part, and who else helps.
  await canvas.findByText(`${i18n.t('council.reshare_my_part', { count: 88 })} ${i18n.t('council.reshare_also', { names: 'Bruno Petit' })}`);
  // The version being moved shows as its move only.
  expect(canvas.queryByText(i18n.t('council.outdated_title', { count: 88 }))).toBeNull();
  await playFindButton(canvasElement, i18n.t('council.reshare_process'));
};
export const MySharePartWaiting = prepareStory(ReshareRunningStory);

// Their part done: the move now waits for the other helper only, named.
const ReshareDoneStory = Template.bind({});
ReshareDoneStory.args = baseArgs;
ReshareDoneStory.parameters = mine([{ ...runningCouncil, reshare: { ...runningCouncil.reshare!, remaining_for_me: 0, remaining: 1 } }]);
ReshareDoneStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.reshare_done_waiting', { names: 'Bruno Petit' }));
  canvas.getByText(i18n.t('council.reshare_running', { count: 1 }));
  expect(canvas.queryByRole('button', { name: i18n.t('council.reshare_process') })).toBeNull();
};
export const MyPartDoneWaitingForOthers = prepareStory(ReshareDoneStory);

// A server that keeps returning the same batch: the vault stops instead of
// looping, and says so.
const RESHARE_SESSION = '0c0c0c0c-0000-4000-8000-000000000001';
const ReshareStalledStory = Template.bind({});
ReshareStalledStory.args = baseArgs;
ReshareStalledStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilsMine({ body: { mfa_enforced: true, councils: [runningCouncil] } }),
      councilRequestsHandler([]),
      handleGetApiCouncilsReshareBySessionIdBatch({
        body: {
          session_id: RESHARE_SESSION,
          council_id: 'dinum',
          helper_slots: [1, 2],
          my_slot: 1,
          target_roster_version: 2,
          target_threshold: 2,
          chain: [sampleRosterVersion(), sampleRosterVersion({ version: 2 })],
          transfer_keys_done: true,
          escrows: [],
          remaining: 88,
        },
      }),
      handlePostApiCouncilsReshareBySessionIdSubShares({ body: { moved: 0, remaining: 88, remaining_for_me: 88 } }),
    ],
  },
  encryption: {
    request: async (type: string, payload?: unknown) =>
      type === MSG_VAULT_COUNCIL_RESHARE_BATCH ? { keys: null, subShares: { escrows: [] } } : defaultVaultRequest(type, payload),
  },
};
ReshareStalledStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.reshare_process')));
  await within(canvasElement).findByText(i18n.t('council.reshare_stalled'));
  await expect(await playFindButton(canvasElement, i18n.t('council.reshare_process'))).toBeEnabled();
};
export const ReshareStalled = prepareStory(ReshareStalledStory);

// A broken or emptied configuration deletes nothing; it only stops changes.
const NotConfiguredStory = Template.bind({});
NotConfiguredStory.args = baseArgs;
NotConfiguredStory.parameters = mine(
  [
    custodianCouncil({
      configured: false,
      blocked: [
        { email: 'dsi@numerique.gouv.fr', name: null, member: false, reason: 'email-mismatch' },
        { email: 'emile.petit@numerique.gouv.fr', name: 'Émile Petit', member: false, reason: 'not-onboarded' },
      ],
    }),
  ],
  false
);
NotConfiguredStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.not_configured_title'));
  canvas.getByText(i18n.t('council.not_configured'));
  canvas.getByText(i18n.t('council.mfa_not_enforced'));
  canvas.getByText(i18n.t('council.blocked_email_mismatch', { email: 'dsi@numerique.gouv.fr' }));
  canvas.getByText(i18n.t('council.blocked_not_onboarded', { name: 'Émile Petit' }));
  // In the alert's own colour, no list.
  expect(canvas.queryByRole('list')).toBeNull();
};
export const ConfigurationIssues = prepareStory(NotConfiguredStory);

// Out of the configuration with a team that replaces it: its people move on their own, the custodians keep serving them meanwhile.
const ReplacedStory = Template.bind({});
ReplacedStory.args = baseArgs;
ReplacedStory.parameters = mine([
  custodianCouncil({
    configured: false,
    replaced_by: 'Équipe sécurité DINUM 2027',
    health: { escrows: 412, ok: 412, at_risk: 0, lost: 0, lost_names: [], outdated: [], absent: [], absence_days: 90, team_ready: true },
  }),
]);
ReplacedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.not_configured_title'));
  // How many are left, and how to reach them.
  canvas.getByText(i18n.t('council.not_configured_replaced', { to: 'Équipe sécurité DINUM 2027', count: 412 }));
  canvas.getByText(i18n.t('council.not_configured_remind', { count: 412 }));
};
export const ReplacedByAnotherTeam = prepareStory(ReplacedStory);

// A custodian of several councils: a list first, the one waiting on them on top,
// then a page per council and a way back to the list.
const SeveralStory = Template.bind({});
SeveralStory.args = baseArgs;
SeveralStory.parameters = mine(
  [
    custodianCouncil({
      council_id: 'dgfip',
      label: 'RSSI DGFiP',
      my_slot: 3,
      health: { escrows: 2400, ok: 2400, at_risk: 0, lost: 0, lost_names: [], outdated: [], absent: [], absence_days: 90, team_ready: true },
    }),
    custodianCouncil(requestCounts([request])),
  ],
  true,
  [request]
);
SeveralStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await playFindHeading(canvasElement, i18n.t('council.custodian_title'));
  const open = await canvas.findAllByRole('button', { name: new RegExp(i18n.t('council.open_council', { council: '' })) });
  expect(open.map((b) => b.getAttribute('aria-label'))).toEqual([
    i18n.t('council.open_council', { council: COUNCIL_LABEL }),
    i18n.t('council.open_council', { council: 'RSSI DGFiP' }),
  ]);
  canvas.getByText(i18n.t('council.pending_chip', { count: 1 }));
  // No request shown before a council is opened.
  expect(canvas.queryByText('Ursula Roux')).toBeNull();

  await userEvent.click(open[0]);
  await playFindHeading(canvasElement, COUNCIL_LABEL);
  await canvas.findByText('Ursula Roux');
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.all_councils')));
  await playFindHeading(canvasElement, i18n.t('council.custodian_title'));
};
export const SeveralCouncils = prepareStory(SeveralStory);

// After a resharing, a helper sent parts that do not match what it committed
// to: the custodians who received them refused them, and the council is told who.
const FaultyStory = Template.bind({});
FaultyStory.args = baseArgs;
FaultyStory.parameters = mine([
  custodianCouncil({
    health: { escrows: 128, ok: 0, at_risk: 125, lost: 3, lost_names: [], outdated: [], absent: [], absence_days: 90, team_ready: true },
    faulty_reshares: [{ helper_name: 'Bruno Petit', escrows: 3 }],
  }),
]);
FaultyStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.faulty_reshare_title', { name: 'Bruno Petit', count: 3 }));
  canvas.getByText(i18n.t('council.health_lost', { count: 3 }));
};
export const InvalidPartsFromAHelper = prepareStory(FaultyStory);

// A new custodian opens their space: their vault checks, in the background, the
// parts a resharing gave them, and the result shows once the server has it.
const escrowIds = ['e5c0e5c0-0000-4000-8000-000000000001', 'e5c0e5c0-0000-4000-8000-000000000002'];
let uploaded: CouncilCheckResultsBody['results'] = [];

const CheckStory = Template.bind({});
CheckStory.args = baseArgs;
CheckStory.parameters = {
  msw: {
    handlers: [
      councilRequestsHandler([]),
      handleGetApiCouncilsMine(() =>
        HttpResponse.json({
          mfa_enforced: true,
          councils: [
            uploaded.length === 0
              ? custodianCouncil({ shares_to_check: 2 })
              : custodianCouncil({
                  health: {
                    escrows: 128,
                    ok: 127,
                    at_risk: 1,
                    lost: 0,
                    lost_names: [],
                    outdated: [],
                    absent: [],
                    absence_days: 90,
                    team_ready: true,
                  },
                  faulty_reshares: [{ helper_name: 'Bruno Petit', escrows: 1 }],
                }),
          ],
        })
      ),
      handleGetApiCouncilsByCouncilIdSharesToCheck(() =>
        HttpResponse.json({
          council_id: 'dinum',
          escrows:
            uploaded.length === 0
              ? escrowIds.map((id) => ({
                  escrow_id: id,
                  user_id: sampleCouncilMembers[1].user_id,
                  record: sampleCouncilEscrowRecord,
                  capsule: { kind: 'direct' as const, generation: 1, slot: 1, wrapped_share: sampleCouncilEscrowRecord.escrow_signature },
                }))
              : [],
          remaining: uploaded.length === 0 ? 2 : 0,
        })
      ),
      handlePostApiCouncilsByCouncilIdSharesChecked(async ({ request }) => {
        uploaded = ((await request.json()) as CouncilCheckResultsBody).results;

        return HttpResponse.json({ checked: uploaded.length, invalid: uploaded.filter((r) => !r.valid).length });
      }),
    ],
  },
  encryption: {
    request: async (type: string, payload?: unknown) =>
      type === MSG_VAULT_COUNCIL_CHECK_SHARES
        ? {
            results: [
              { escrow_id: escrowIds[0], valid: true, faulty_helper_slot: null },
              { escrow_id: escrowIds[1], valid: false, faulty_helper_slot: 2 },
            ],
          }
        : defaultVaultRequest(type, payload),
  },
};
CheckStory.beforeEach = () => {
  uploaded = [];
};
CheckStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  await canvas.findByText(i18n.t('council.faulty_reshare_title', { name: 'Bruno Petit', count: 1 }));
  await waitFor(() => expect(uploaded).toEqual([expect.objectContaining({ valid: true }), expect.objectContaining({ faulty_helper_slot: 2 })]));
};
export const ChecksReceivedParts = prepareStory(CheckStory);

// A long list: search, filter (with the count of each) and pages, applied by the server.
const crowd = Array.from({ length: 12 }, (_, i) => ({
  ...request,
  id: `5d6e7f80-0000-4000-8000-${String(i + 10).padStart(12, '0')}`,
  user_name: i === 7 ? 'Victor Lemaire' : `Personne ${i + 1}`,
  user_email: i === 7 ? 'victor.lemaire@numerique.gouv.fr' : `personne.${i + 1}@numerique.gouv.fr`,
  stage: i % 3 === 0 ? ('awaiting_meeting' as const) : ('collecting' as const),
  // Approvals only follow a meeting: someone handed over in person.
  contributors: i % 3 === 0 ? [] : [{ slot: 2, name: 'Bruno Petit', in_person: true }],
  can_contribute: i % 2 === 0,
  created_at_millis: NOW - (i < 2 ? 4 : 1) * DAY,
  expires_at_millis: NOW + (i + 1) * 60 * 60 * 1000,
}));

const ManyRequestsStory = Template.bind({});
ManyRequestsStory.args = baseArgs;
ManyRequestsStory.parameters = mine([custodianCouncil(requestCounts(crowd))], true, crowd);
ManyRequestsStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.requests_title_count', { count: 12 }));
  // Five a page, those the custodian can act on first.
  expect(
    canvas.getAllByRole('button', { name: new RegExp(`^(${i18n.t('council.hand_over_in_person')}|${i18n.t('council.approve_remotely')})$`) })
  ).toHaveLength(5);
  canvas.getByText('Personne 1');
  expect(canvas.queryByText('Personne 2')).toBeNull();
  canvas.getByText(i18n.t('council.requests_page', { page: 1, count: 3 }));
  expect(canvas.getByRole('button', { name: i18n.t('council.requests_previous') })).toBeDisabled();
  await userEvent.click(canvas.getByRole('button', { name: i18n.t('council.requests_next') }));
  await canvas.findByText(i18n.t('council.requests_page', { page: 2, count: 3 }));
  await canvas.findByText('Personne 11');
};
export const ManyRequests = prepareStory(ManyRequestsStory);

const SearchRequestsStory = Template.bind({});
SearchRequestsStory.args = baseArgs;
SearchRequestsStory.parameters = ManyRequestsStory.parameters;
SearchRequestsStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await userEvent.type(await canvas.findByLabelText(i18n.t('council.requests_search')), 'lemaire');
  await canvas.findByText('Victor Lemaire');
  expect(canvas.queryByText('Personne 1')).toBeNull();
  expect(canvas.queryByRole('button', { name: i18n.t('council.requests_next') })).toBeNull();
};
export const SearchRequests = prepareStory(SearchRequestsStory);

const FilterRequestsStory = Template.bind({});
FilterRequestsStory.args = baseArgs;
FilterRequestsStory.parameters = ManyRequestsStory.parameters;
FilterRequestsStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  const body = within(document.body);
  await userEvent.click(await canvas.findByRole('button', { name: i18n.t('council.requests_filter') }));
  // Only the filters that match something, each with its count.
  await body.findByRole('menuitem', { name: new RegExp(i18n.t('council.requests_filter_all', { count: 12 }).replace(/[()]/g, '\\$&')) });
  expect(
    body.queryByRole('menuitem', { name: new RegExp(i18n.t('council.requests_filter_released', { count: 0 }).replace(/[()]/g, '\\$&')) })
  ).toBeNull();
  await userEvent.click(
    body.getByRole('menuitem', { name: new RegExp(i18n.t('council.requests_filter_stalled', { count: 2 }).replace(/[()]/g, '\\$&')) })
  );
  await waitFor(() => expect(canvas.queryByText('Personne 3')).toBeNull());
  canvas.getByText('Personne 1');
  canvas.getByText('Personne 2');
};
export const FilterRequests = prepareStory(FilterRequestsStory);

// Setups at risk and lost: what each means for the custodian, said under the chips.
const HealthIssuesStory = Template.bind({});
HealthIssuesStory.args = baseArgs;
HealthIssuesStory.parameters = mine([
  custodianCouncil({
    health: {
      escrows: 128,
      ok: 119,
      at_risk: 6,
      lost: 3,
      lost_names: ['Élise Bernard', 'Hugo Lambert'],
      outdated: [],
      absent: [],
      absence_days: 90,
      team_ready: true,
    },
  }),
]);
HealthIssuesStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.health_at_risk', { count: 6 }));
  canvas.getByText(i18n.t('council.health_at_risk_explained', { count: 6 }));
  canvas.getByText(i18n.t('council.health_lost_explained', { count: 3 }));
  // Named, so the team can tell them.
  canvas.getByText(
    i18n.t('council.health_lost_names', {
      names: new Intl.ListFormat(i18n.language, { type: 'conjunction' }).format(['Élise Bernard', 'Hugo Lambert']),
      count: 2,
    })
  );
  // The third protects an access its owner has replaced: nobody to tell.
  canvas.getByText(i18n.t('council.health_lost_replaced', { count: 1 }));
  expect(canvas.queryByText(i18n.t('council.health_ok'))).toBeNull();
};
export const HealthIssues = prepareStory(HealthIssuesStory);

// Members without encryption broke the team: nobody can join it, so nobody is told to join again yet.
const TeamToRepairStory = Template.bind({});
TeamToRepairStory.args = baseArgs;
TeamToRepairStory.parameters = mine([
  custodianCouncil({
    health: {
      escrows: 128,
      ok: 0,
      at_risk: 0,
      lost: 128,
      lost_names: ['Élise Bernard'],
      outdated: [],
      absent: [],
      absence_days: 90,
      team_ready: false,
    },
  }),
]);
TeamToRepairStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.health_lost_repair', { count: 128 }));
  expect(canvas.queryByText(i18n.t('council.health_lost_explained', { count: 128 }))).toBeNull();
  expect(canvas.queryByText(i18n.t('council.health_lost_names', { names: 'Élise Bernard', count: 1 }))).toBeNull();
};
export const TeamToRepair = prepareStory(TeamToRepairStory);

// A custodian long without a sign-in: named, with what to do, and the setups the margin no longer covers.
const AbsentMemberStory = Template.bind({});
AbsentMemberStory.args = baseArgs;
AbsentMemberStory.parameters = mine([
  custodianCouncil({
    health: { escrows: 128, ok: 0, at_risk: 128, lost: 0, lost_names: [], outdated: [], absent: ['Bob Dupont'], absence_days: 90, team_ready: true },
  }),
]);
AbsentMemberStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.absent_title', { count: 90 }));
  canvas.getByText('Bob Dupont');
  canvas.getByText(i18n.t('council.absent_description'));
  canvas.getByText(i18n.t('council.health_at_risk', { count: 128 }));
};
export const AbsentMember = prepareStory(AbsentMemberStory);

// A member who started over: already in the team, not a newcomer who cannot join.
const InactiveMemberStory = Template.bind({});
InactiveMemberStory.args = baseArgs;
InactiveMemberStory.parameters = mine([
  custodianCouncil({
    blocked: [{ email: 'bob.dupont@numerique.gouv.fr', name: 'Bob Dupont', member: true, reason: 'not-onboarded' }],
    health: { escrows: 128, ok: 0, at_risk: 128, lost: 0, lost_names: [], outdated: [], absent: [], absence_days: 90, team_ready: true },
  }),
]);
InactiveMemberStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.inactive_members_title', { count: 1, names: 'Bob Dupont' }));
  canvas.getByText(i18n.t('council.inactive_members_description', { count: 1 }));
  // The three ways out, as a list.
  expect(within(canvas.getByRole('list')).getAllByRole('listitem')).toHaveLength(3);
  canvas.getByText(i18n.t('council.inactive_members_if_left', { count: 1 }));
  expect(canvas.queryByText(i18n.t('council.blocked'))).toBeNull();
};
export const MemberWithoutEncryption = prepareStory(InactiveMemberStory);
