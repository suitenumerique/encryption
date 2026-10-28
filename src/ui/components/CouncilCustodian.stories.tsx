import { Meta, StoryFn } from '@storybook/react';
import { expect, userEvent, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import type { CouncilsMine } from '@encryption/src/ui/api/council-client';
import { handleGetApiCouncilsMine } from '@encryption/src/ui/api/generated/msw.gen';
import { CouncilCustodian } from '@encryption/src/ui/components/CouncilCustodian';
import { COUNCIL_LABEL, custodianCouncil } from '@encryption/src/ui/testing/council-stories';
import { sampleCouncilMembers, sampleRosterVersion } from '@encryption/src/ui/testing/fixtures';

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
            'The custodian space: one card per recovery council the user sits in or is invited to, with what waits on them (a change to sign, requests to approve or hand over in person, setups to move after a membership change). Opened from the encryption settings, or as the `custodian` settings section.',
        },
      },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <CouncilCustodian {...args} />;
const baseArgs = { getIdToken: async () => 'mock-jwt-token', userId: sampleCouncilMembers[0].user_id, onClose: () => console.log('onClose') };

function mine(councils: CouncilsMine['councils'], mfa = true) {
  return { msw: { handlers: [handleGetApiCouncilsMine({ body: { mfa_enforced: mfa, councils } })] } };
}

const request = {
  id: '5d6e7f80-0000-4000-8000-000000000001',
  user_name: 'Ursula Roux',
  user_email: 'ursula.roux@numerique.gouv.fr',
  created_at_millis: NOW - DAY,
  expires_at_millis: NOW + 6 * DAY,
  stage: 'collecting' as const,
  contributors: [],
  my_contribution: 'none' as const,
  can_contribute: true,
};

const EmptyStory = Template.bind({});
EmptyStory.args = baseArgs;
EmptyStory.parameters = mine([]);
EmptyStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.custodian_none'));
};
export const NotACustodian = prepareStory(EmptyStory);

// Named in the configuration, the council not in force yet: accept the role.
const InvitedStory = Template.bind({});
InvitedStory.args = baseArgs;
InvitedStory.parameters = mine([
  custodianCouncil({
    role: 'invited',
    my_slot: null,
    chain: [],
    health: { escrows: 0, ok: 0, at_risk: 0, lost: 0, outdated: [] },
    proposal: { roster: sampleRosterVersion({ signatures: [] }), quorum_missing: 0, pending_members: [], signed_by_me: false, may_sign: true },
  }),
]);
InvitedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.invitation_title'));
  canvas.getByText(i18n.t('council.role_invited'));
  await playFindButton(canvasElement, i18n.t('council.review_and_accept'));
  // An invitee sees no request and no health: those are custodians' business.
  expect(canvas.queryByText(i18n.t('council.requests_title'))).toBeNull();
};
export const Invited = prepareStory(InvitedStory);

// A request: approve remotely while approvals are collected, or hand over in person.
const RequestsStory = Template.bind({});
RequestsStory.args = baseArgs;
RequestsStory.parameters = mine([
  custodianCouncil({
    requests: [
      request,
      {
        ...request,
        id: '5d6e7f80-0000-4000-8000-000000000002',
        user_name: 'Victor Lemaire',
        user_email: 'victor.lemaire@numerique.gouv.fr',
        stage: 'awaiting_meeting',
        contributors: [{ slot: 2, name: 'Bruno Petit', in_person: false }],
      },
    ],
  }),
]);
RequestsStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText('Ursula Roux');
  canvas.getByText(i18n.t('council.stage_awaiting_meeting'));
  canvas.getByText(i18n.t('council.request_contributors', { names: 'Bruno Petit' }), { exact: false });
  // Remote approval only while approvals are collected; the meeting step takes a share in person.
  expect(canvas.getAllByRole('button', { name: i18n.t('council.approve_remotely') })).toHaveLength(1);
  expect(canvas.getAllByRole('button', { name: i18n.t('council.hand_over_in_person') })).toHaveLength(2);
};
export const Requests = prepareStory(RequestsStory);

const StopRequestStory = Template.bind({});
StopRequestStory.args = baseArgs;
StopRequestStory.parameters = mine([custodianCouncil({ requests: [request] })]);
StopRequestStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.abort')));
  await playFindButton(canvasElement, i18n.t('council.abort_confirm'));
};
export const StopRequestConfirmation = prepareStory(StopRequestStory);

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

// After a replacement: setups still split over the old version, to move.
const OutdatedStory = Template.bind({});
OutdatedStory.args = baseArgs;
OutdatedStory.parameters = mine([
  custodianCouncil({
    chain: [sampleRosterVersion(), sampleRosterVersion({ version: 2 })],
    health: { escrows: 128, ok: 40, at_risk: 88, lost: 0, outdated: [{ version: 1, escrows: 88 }] },
  }),
]);
OutdatedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.outdated_title', { count: 88, version: 1 }));
  canvas.getByText(i18n.t('council.health_at_risk', { count: 88 }));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.reshare_button')));
  await playFindHeading(canvasElement, i18n.t('council.reshare_title', { from: 1, to: 2 }));
  // Exactly the source threshold, the custodian first.
  expect(canvas.getByLabelText(i18n.t('council.reshare_me', { name: 'Alice Martin' }))).toBeChecked();
  await playFindButton(canvasElement, i18n.t('council.reshare_start'));
};
export const MoveSetups = prepareStory(OutdatedStory);

const ReshareRunningStory = Template.bind({});
ReshareRunningStory.args = baseArgs;
ReshareRunningStory.parameters = mine([
  custodianCouncil({
    chain: [sampleRosterVersion(), sampleRosterVersion({ version: 2 })],
    health: { escrows: 128, ok: 40, at_risk: 88, lost: 0, outdated: [{ version: 1, escrows: 88 }] },
    reshare: {
      session_id: '0c0c0c0c-0000-4000-8000-000000000001',
      source_version: 1,
      target_version: 2,
      helper_slots: [1, 2],
      i_am_helper: true,
      remaining_for_me: 88,
      remaining: 88,
    },
  }),
]);
ReshareRunningStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.reshare_my_part', { count: 88 }));
  await playFindButton(canvasElement, i18n.t('council.reshare_process'));
};
export const MySharePartWaiting = prepareStory(ReshareRunningStory);

// A broken or emptied configuration deletes nothing; it only stops changes.
const NotConfiguredStory = Template.bind({});
NotConfiguredStory.args = baseArgs;
NotConfiguredStory.parameters = mine(
  [
    custodianCouncil({
      configured: false,
      blocked: [{ email: 'dsi@numerique.gouv.fr', reason: 'email-mismatch' }],
    }),
  ],
  false
);
NotConfiguredStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.not_configured'));
  canvas.getByText(i18n.t('council.mfa_not_enforced'));
  canvas.getByText(i18n.t('council.blocked_email_mismatch', { email: 'dsi@numerique.gouv.fr' }));
};
export const ConfigurationIssues = prepareStory(NotConfiguredStory);

// A custodian of several councils: one card each, every action naming its council.
const SeveralStory = Template.bind({});
SeveralStory.args = baseArgs;
SeveralStory.parameters = mine([
  custodianCouncil({ requests: [request] }),
  custodianCouncil({ council_id: 'dgfip', label: 'RSSI DGFiP', my_slot: 3, health: { escrows: 2400, ok: 2400, at_risk: 0, lost: 0, outdated: [] } }),
]);
SeveralStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(COUNCIL_LABEL);
  canvas.getByText('RSSI DGFiP');
  expect(canvas.getAllByText(i18n.t('council.health_ok'))).toHaveLength(2);
};
export const SeveralCouncils = prepareStory(SeveralStory);
