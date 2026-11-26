import { Meta, StoryFn } from '@storybook/react';
import { expect, fn, userEvent, waitFor, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { MSG_VAULT_COUNCIL_COMPLETE_RECOVERY, MSG_VAULT_COUNCIL_REQUEST_KEY } from '@encryption/src/shared/constants';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import type { MyCouncilRequest } from '@encryption/src/ui/api/council-client';
import {
  handleGetApiCouncilRecoveryRequestsByIdShares,
  handleGetApiCouncilRecoveryRequestsMine,
  handleGetApiCouncilsForMe,
  handlePostApiCouncilRecoveryRequests,
  handlePostApiCouncilRecoveryRequestsByIdRefuse,
} from '@encryption/src/ui/api/generated/msw.gen';
import { CouncilRecovery } from '@encryption/src/ui/components/CouncilRecovery';
import { COUNCIL_LABEL, forMe } from '@encryption/src/ui/testing/council-stories';
import { sampleCouncilEscrowRecord, sampleFingerprint, samplePublicKey } from '@encryption/src/ui/testing/fixtures';
import { defaultVaultRequest } from '@encryption/src/ui/testing/mock-encryption';

type ComponentType = typeof CouncilRecovery;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

// The expiry is shown as a date, so "now" is pinned.
const NOW = Date.UTC(2026, 9, 28, 9);

export default {
  title: 'Preview/Modals/CouncilRecovery',
  component: CouncilRecovery,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: true,
      date: new Date(NOW),
      docs: {
        description: {
          component:
            'A locked-out user asks their recovery council: "request in progress", then "go and see one of these people" with the code the custodian checks on this screen. Reached from the "Restore your encryption" choices.',
        },
      },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <CouncilRecovery {...args} />;
const baseArgs = { getIdToken: async () => 'mock-jwt-token', onRecovered: fn(), onBack: () => console.log('onBack') };

function request(overrides: Partial<MyCouncilRequest> = {}): MyCouncilRequest {
  return {
    id: '5d6e7f80-0000-4000-8000-000000000001',
    council_label: COUNCIL_LABEL,
    stage: 'in_progress',
    created_at_millis: NOW,
    expires_at_millis: NOW + 7 * 24 * 60 * 60 * 1000,
    meet: [],
    ephemeral_fingerprint: sampleFingerprint,
    vault_active: true,
    vault_created_at_millis: Date.UTC(2026, 0, 12),
    ...overrides,
  };
}

const IntroStory = Template.bind({});
IntroStory.args = baseArgs;
IntroStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilRecoveryRequestsMine({ body: { request: null, ended: null } }),
      handleGetApiCouncilsForMe({ body: forMe({ escrow: {} }) }),
      handlePostApiCouncilRecoveryRequests({ body: { id: request().id, expires_at_millis: request().expires_at_millis } }),
    ],
  },
};
IntroStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('council.recovery_title'));
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.recovery_intro'));
  // The council named once, as a card.
  expect(canvas.getAllByText(COUNCIL_LABEL)).toHaveLength(1);
  await playFindButton(canvasElement, i18n.t('council.ask_button'));
};
export const Ask = prepareStory(IntroStory);

// The council holds a vault the user replaced: they may want back what came
// before rather than the vault of the last few hours, so they choose.
const asked = fn();
const PREVIOUS_COUNCIL = 'Équipe sécurité DINUM 2025';
const ChooseVaultStory = Template.bind({});
ChooseVaultStory.args = baseArgs;
ChooseVaultStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilRecoveryRequestsMine({ body: { request: null, ended: null } }),
      handleGetApiCouncilsForMe({
        body: forMe({
          escrow: {},
          vaults: [
            {
              escrow_id: '7f1c2b3a-0000-4000-8000-000000000001',
              council_label: COUNCIL_LABEL,
              active: true,
              created_at_millis: Date.UTC(2026, 9, 27),
              disabled_at_millis: null,
            },
            // Kept by the team the user left when they moved: only it can give that vault back.
            {
              escrow_id: '7f1c2b3a-0000-4000-8000-000000000002',
              council_label: PREVIOUS_COUNCIL,
              active: false,
              created_at_millis: Date.UTC(2025, 2, 1),
              disabled_at_millis: Date.UTC(2026, 9, 27),
            },
          ],
        }),
      }),
      handlePostApiCouncilRecoveryRequests(async ({ request: req }) => {
        asked(((await req.json()) as { escrow_id?: string }).escrow_id);

        return Response.json({ id: request().id, expires_at_millis: request().expires_at_millis });
      }),
    ],
  },
};
ChooseVaultStory.play = async ({ canvasElement }) => {
  asked.mockClear();
  const canvas = within(canvasElement);
  await playFindHeading(canvasElement, i18n.t('council.recovery_title'));
  const current = await canvas.findByRole('radio', { name: new RegExp(i18n.t('council.vault_current')) });
  await expect(current).toBeChecked();
  await expect(canvas.getByText(COUNCIL_LABEL)).toBeInTheDocument();
  const older = canvas.getByRole('radio', { name: new RegExp(i18n.t('council.vault_retired', { date: new Date(Date.UTC(2026, 9, 27)) })) });
  await userEvent.click(older);
  await expect(older).toBeChecked();
  await expect(canvas.getByText(PREVIOUS_COUNCIL)).toBeInTheDocument();
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.ask_button')));
  await waitFor(() => expect(asked).toHaveBeenCalledWith('7f1c2b3a-0000-4000-8000-000000000002'));
};
export const ChooseVault = prepareStory(ChooseVaultStory);

// After the meeting, while the others approve remotely: nothing about who, or how many.
const InProgressStory = Template.bind({});
InProgressStory.args = baseArgs;
InProgressStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilRecoveryRequestsMine({ body: { request: request(), ended: null } }),
      handlePostApiCouncilRecoveryRequestsByIdRefuse({ body: { refused: true } }),
    ],
  },
};
InProgressStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await playFindHeading(canvasElement, i18n.t('council.in_progress_title'));
  canvas.getByText(i18n.t('council.in_progress_description'));
  // The screen checks by itself: cancelling is the one action.
  await playFindButton(canvasElement, i18n.t('council.cancel_request'));
  expect(canvas.queryByText('Alice Martin')).toBeNull();
};
export const InProgress = prepareStory(InProgressStory);

// Cancelling cannot be undone: a dialog says what it costs first.
const CancelRequestStory = Template.bind({});
CancelRequestStory.args = baseArgs;
CancelRequestStory.parameters = InProgressStory.parameters;
CancelRequestStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.cancel_request')));
  const dialog = within(await within(document.body).findByRole('dialog'));
  await dialog.findByText(i18n.t('council.cancel_body'));
  await dialog.findByRole('button', { name: i18n.t('council.cancel_keep') });
};
export const CancelRequestConfirmation = prepareStory(CancelRequestStory);

// Right after asking: the names of who can hand over the first share, and the
// code they check on this screen. Remote approvals only come after.
const MeetStory = Template.bind({});
MeetStory.args = baseArgs;
MeetStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilRecoveryRequestsMine({
        body: { request: request({ stage: 'meet', meet: [{ name: 'Bruno Petit' }, { name: 'Chloé Durand' }] }), ended: null },
      }),
    ],
  },
};
MeetStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await playFindHeading(canvasElement, i18n.t('council.meet_title'));
  canvas.getByText('Bruno Petit');
  canvas.getByText('Chloé Durand');
  canvas.getByText(i18n.t('council.meet_code_hint'));
  // The QR code first, its digits on demand.
  await canvas.findByRole('img', { name: i18n.t('council.meet_qr_label') });
  expect(canvas.queryByLabelText(sampleFingerprint.match(/\d{5}/g)!.join(' '))).toBeNull();
  await userEvent.click(await playFindButton(canvasElement, i18n.t('device_approval.show_code')));
  await canvas.findByLabelText(sampleFingerprint.match(/\d{5}/g)!.join(' '));
  // Back to the QR code, the state the screen opens on.
  await userEvent.click(await playFindButton(canvasElement, i18n.t('device_approval.show_qr')));
  await canvas.findByRole('img', { name: i18n.t('council.meet_qr_label') });
};
export const GoAndSee = prepareStory(MeetStory);

// The request was opened elsewhere: only that browser can receive the shares.
const OtherBrowserStory = Template.bind({});
OtherBrowserStory.args = baseArgs;
OtherBrowserStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilRecoveryRequestsMine({ body: { request: request(), ended: null } }),
      handlePostApiCouncilRecoveryRequestsByIdRefuse({ body: { refused: true } }),
    ],
  },
  encryption: {
    request: async (type: string, payload?: unknown) => (type === MSG_VAULT_COUNCIL_REQUEST_KEY ? null : defaultVaultRequest(type, payload)),
  },
};
OtherBrowserStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.other_browser'));
  // Cancelling from here is confirmed first, like everywhere else.
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.cancel_request')));
  await within(await within(document.body).findByRole('dialog')).findByText(i18n.t('council.cancel_body'));
};
export const StartedFromAnotherBrowser = prepareStory(OtherBrowserStory);

const UnavailableStory = Template.bind({});
UnavailableStory.args = baseArgs;
UnavailableStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilRecoveryRequestsMine({ body: { request: null, ended: null } }),
      handleGetApiCouncilsForMe({ body: forMe({ escrow: { health: { live: 1, threshold: 2, status: 'lost', outdated: false } } }) }),
    ],
  },
};
UnavailableStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.recovery_unavailable'));
};
export const Unavailable = prepareStory(UnavailableStory);

// Released: the shares are combined in this browser and the caller takes over.
const releasedHandlers = [
  handleGetApiCouncilRecoveryRequestsMine({ body: { request: request({ stage: 'released' }), ended: null } }),
  handleGetApiCouncilRecoveryRequestsByIdShares({
    body: {
      request_id: request().id,
      council_id: 'dinum',
      user_id: '00000000-0000-0000-0000-000000000000',
      owner_identity_public_key: samplePublicKey.signature_public_key,
      generation: 1,
      threshold: 2,
      share_commitments: sampleCouncilEscrowRecord.share_commitments,
      lang: 'french',
      escrow: sampleCouncilEscrowRecord,
      chain: [],
      contributions: [],
    },
  }),
];
const ReleasedStory = Template.bind({});
ReleasedStory.args = baseArgs;
ReleasedStory.parameters = { msw: { handlers: releasedHandlers } };
ReleasedStory.play = async ({ args }) => {
  await waitFor(() => expect(args.onRecovered).toHaveBeenCalledOnce());
};
export const Released = prepareStory(ReleasedStory);

// Released, but this browser no longer holds the request's key: cancelling and asking again is the way out.
const ReleasedWithoutKeyStory = Template.bind({});
ReleasedWithoutKeyStory.args = baseArgs;
ReleasedWithoutKeyStory.parameters = {
  msw: { handlers: [handleGetApiCouncilRecoveryRequestsMine({ body: { request: request({ stage: 'released' }), ended: null } })] },
  encryption: OtherBrowserStory.parameters.encryption,
};
ReleasedWithoutKeyStory.play = async ({ canvasElement, args }) => {
  await within(canvasElement).findByText(i18n.t('council.other_browser'));
  await playFindButton(canvasElement, i18n.t('council.cancel_request'));
  expect(args.onRecovered).not.toHaveBeenCalled();
};
export const ReleasedWithoutKey = prepareStory(ReleasedWithoutKeyStory);

// Released, but the parts do not combine here: no endless retry, the user tries
// again or stops the request to ask again.
const refused = fn();
const CombineFailedStory = Template.bind({});
CombineFailedStory.args = baseArgs;
CombineFailedStory.parameters = {
  msw: {
    handlers: [
      ...releasedHandlers,
      handlePostApiCouncilRecoveryRequestsByIdRefuse(() => {
        refused();

        return Response.json({ refused: true });
      }),
    ],
  },
  encryption: {
    request: async (type: string, payload?: unknown) => {
      if (type === MSG_VAULT_COUNCIL_COMPLETE_RECOVERY) throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'Not enough valid shares');

      return defaultVaultRequest(type, payload);
    },
  },
};
CombineFailedStory.play = async ({ canvasElement, args }) => {
  refused.mockClear();
  await playFindHeading(canvasElement, i18n.t('council.combine_failed_title'));
  await playFindButton(canvasElement, i18n.t('council.retry'));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.combine_restart')));
  // Stopping cannot be undone: confirmed first.
  const dialog = within(await within(document.body).findByRole('dialog'));
  await userEvent.click(await dialog.findByRole('button', { name: i18n.t('council.cancel_confirm') }));
  await waitFor(() => expect(refused).toHaveBeenCalledOnce());
  expect(args.onRecovered).not.toHaveBeenCalled();
};
export const PartsDoNotCombine = prepareStory(CombineFailedStory);

const ended = (reason: 'expired' | 'aborted') => ({
  reason,
  ended_at_millis: NOW - 24 * 60 * 60 * 1000,
  council_label: COUNCIL_LABEL,
  ephemeral_fingerprint: sampleFingerprint,
});

// This browser's request expired while the user was away: said once, then the usual way to ask again.
const ExpiredStory = Template.bind({});
ExpiredStory.args = baseArgs;
ExpiredStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilRecoveryRequestsMine({ body: { request: null, ended: ended('expired') } }),
      handleGetApiCouncilsForMe({ body: forMe({ escrow: {} }) }),
    ],
  },
};
ExpiredStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.ended_expired', { council: COUNCIL_LABEL, date: new Date(NOW - 24 * 60 * 60 * 1000) }));
  await playFindButton(canvasElement, i18n.t('council.ask_again_button'));
};
export const RequestExpired = prepareStory(ExpiredStory);

// A custodian stopped this browser's request.
const AbortedStory = Template.bind({});
AbortedStory.args = baseArgs;
AbortedStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilRecoveryRequestsMine({ body: { request: null, ended: ended('aborted') } }),
      handleGetApiCouncilsForMe({ body: forMe({ escrow: {} }) }),
    ],
  },
};
AbortedStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.ended_aborted', { council: COUNCIL_LABEL }));
  await playFindButton(canvasElement, i18n.t('council.ask_again_button'));
};
export const RequestStopped = prepareStory(AbortedStory);
