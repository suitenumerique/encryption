import { Meta, StoryFn } from '@storybook/react';
import { HttpResponse } from 'msw';
import { expect, userEvent, waitFor, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { MSG_VAULT_COUNCIL_CHECK_SHARES, MSG_VAULT_COUNCIL_RESHARE_BATCH } from '@encryption/src/shared/constants';
import type { CouncilCheckResultsBody } from '@encryption/src/shared/schemas/recovery-council';
import type { CouncilsMine } from '@encryption/src/ui/api/council-client';
import {
  handleGetApiCouncilsByCouncilIdSharesToCheck,
  handleGetApiCouncilsMine,
  handleGetApiCouncilsReshareBySessionIdBatch,
  handlePostApiCouncilsByCouncilIdSharesChecked,
  handlePostApiCouncilsReshareBySessionIdSubShares,
} from '@encryption/src/ui/api/generated/msw.gen';
import { CouncilCustodian } from '@encryption/src/ui/components/CouncilCustodian';
import { COUNCIL_LABEL, custodianCouncil } from '@encryption/src/ui/testing/council-stories';
import { sampleCouncilEscrowRecord, sampleCouncilMembers, sampleRosterVersion } from '@encryption/src/ui/testing/fixtures';
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

// A helper's part of a resharing, not processed yet.
const runningCouncil = custodianCouncil({
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
});

const ReshareRunningStory = Template.bind({});
ReshareRunningStory.args = baseArgs;
ReshareRunningStory.parameters = mine([runningCouncil]);
ReshareRunningStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.reshare_my_part', { count: 88 }));
  await playFindButton(canvasElement, i18n.t('council.reshare_process'));
};
export const MySharePartWaiting = prepareStory(ReshareRunningStory);

// A server that keeps returning the same batch: the vault stops instead of
// looping, and says so.
const RESHARE_SESSION = '0c0c0c0c-0000-4000-8000-000000000001';
const ReshareStalledStory = Template.bind({});
ReshareStalledStory.args = baseArgs;
ReshareStalledStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilsMine({ body: { mfa_enforced: true, councils: [runningCouncil] } }),
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
      handlePostApiCouncilsReshareBySessionIdSubShares({ body: { moved: 0, remaining: 88 } }),
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
  await expect(await playFindButton(canvasElement, i18n.t('settings.done'))).toBeEnabled();
};
export const ReshareStalled = prepareStory(ReshareStalledStory);

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

// After a resharing, a helper sent parts that do not match what it committed
// to: the custodians who received them refused them, and the council is told who.
const FaultyStory = Template.bind({});
FaultyStory.args = baseArgs;
FaultyStory.parameters = mine([
  custodianCouncil({
    health: { escrows: 128, ok: 0, at_risk: 125, lost: 3, outdated: [] },
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
      handleGetApiCouncilsMine(() =>
        HttpResponse.json({
          mfa_enforced: true,
          councils: [
            uploaded.length === 0
              ? custodianCouncil({ shares_to_check: 2 })
              : custodianCouncil({
                  health: { escrows: 128, ok: 127, at_risk: 1, lost: 0, outdated: [] },
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
