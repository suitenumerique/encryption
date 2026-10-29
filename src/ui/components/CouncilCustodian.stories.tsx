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
  threshold: 2,
  my_contribution: 'none' as const,
  can_contribute: true,
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
  dialog.getByRole('button', { name: i18n.t('identity.copy_fingerprint') });
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
    health: { escrows: 0, ok: 0, at_risk: 0, lost: 0, outdated: [] },
    proposal: { roster: sampleRosterVersion({ signatures: [] }), quorum_missing: 0, pending_members: [], signed_by_me: false, may_sign: true },
  }),
]);
InvitedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.invitation_title'));
  canvas.getByText(i18n.t('council.role_invited'));
  await playFindButton(canvasElement, i18n.t('council.review_and_accept'));
  // No code before version 1 is signed.
  expect(canvas.queryByText(i18n.t('council.custodian_code_hint'))).toBeNull();
  // An invitee sees no request and no health: those are custodians' business.
  expect(canvas.queryByText(i18n.t('council.requests_title_count', { count: 0 }))).toBeNull();
};
export const Invited = prepareStory(InvitedStory);

// Two requests: Ursula already met a custodian (remote approval is open), Victor
// met nobody yet (only a share in person, after checking the code).
const RequestsStory = Template.bind({});
RequestsStory.args = baseArgs;
RequestsStory.parameters = mine([
  custodianCouncil({
    requests: [
      { ...request, contributors: [{ slot: 2, name: 'Bruno Petit', in_person: true }] },
      {
        ...request,
        id: '5d6e7f80-0000-4000-8000-000000000002',
        user_name: 'Victor Lemaire',
        user_email: 'victor.lemaire@numerique.gouv.fr',
        stage: 'awaiting_meeting',
      },
    ],
  }),
]);
RequestsStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText('Ursula Roux');
  canvas.getByText(i18n.t('council.stage_awaiting_meeting'));
  // Each row's band says what it asks of this custodian, with its one action.
  canvas.getByText(i18n.t('council.request_nobody_met'));
  canvas.getByText(i18n.t('council.request_met_by', { names: 'Bruno Petit' }));
  // One way each: in person before the meeting, remotely after it.
  expect(canvas.getAllByRole('button', { name: i18n.t('council.approve_remotely') })).toHaveLength(1);
  expect(canvas.getAllByRole('button', { name: i18n.t('council.hand_over_in_person') })).toHaveLength(1);
};
export const Requests = prepareStory(RequestsStory);

const StopRequestStory = Template.bind({});
StopRequestStory.args = baseArgs;
StopRequestStory.parameters = mine([custodianCouncil({ requests: [request] })]);
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
  await canvas.findByText(i18n.t('council.outdated_title', { count: 88, to: 2 }));
  // The move is the remedy: no separate explanation of the risk.
  expect(canvas.queryByText(i18n.t('council.health_at_risk_explained', { count: 88 }))).toBeNull();
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
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.reshare_my_part', { count: 88 }));
  // The version being moved shows as its move only.
  expect(canvas.queryByText(i18n.t('council.outdated_title', { count: 88, to: 2 }))).toBeNull();
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
  // In the alert's own colour, no list.
  expect(canvas.queryByRole('list')).toBeNull();
};
export const ConfigurationIssues = prepareStory(NotConfiguredStory);

// A custodian of several councils: a list first, the one waiting on them on top,
// then a page per council and a way back to the list.
const SeveralStory = Template.bind({});
SeveralStory.args = baseArgs;
SeveralStory.parameters = mine([
  custodianCouncil({ council_id: 'dgfip', label: 'RSSI DGFiP', my_slot: 3, health: { escrows: 2400, ok: 2400, at_risk: 0, lost: 0, outdated: [] } }),
  custodianCouncil({ requests: [request] }),
]);
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

// A long list: search, filter (with the count of each) and pages, all in the browser.
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
ManyRequestsStory.parameters = mine([custodianCouncil({ requests: crowd })]);
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
  canvas.getByText('Personne 11');
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
HealthIssuesStory.parameters = mine([custodianCouncil({ health: { escrows: 128, ok: 120, at_risk: 6, lost: 2, outdated: [] } })]);
HealthIssuesStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.health_at_risk', { count: 6 }));
  canvas.getByText(i18n.t('council.health_at_risk_explained', { count: 6 }));
  canvas.getByText(i18n.t('council.health_lost_explained', { count: 2 }));
  expect(canvas.queryByText(i18n.t('council.health_ok'))).toBeNull();
};
export const HealthIssues = prepareStory(HealthIssuesStory);
