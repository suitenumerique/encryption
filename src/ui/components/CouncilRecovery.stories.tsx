import { Meta, StoryFn } from '@storybook/react';
import { expect, fn, userEvent, waitFor, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { MSG_VAULT_COUNCIL_REQUEST_KEY } from '@encryption/src/shared/constants';
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
import { sampleCouncilEscrowRecord, sampleFingerprint } from '@encryption/src/ui/testing/fixtures';
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
    ...overrides,
  };
}

const IntroStory = Template.bind({});
IntroStory.args = baseArgs;
IntroStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilRecoveryRequestsMine({ body: { request: null } }),
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

// After the meeting, while the others approve remotely: nothing about who, or how many.
const InProgressStory = Template.bind({});
InProgressStory.args = baseArgs;
InProgressStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilRecoveryRequestsMine({ body: { request: request() } }),
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
        body: { request: request({ stage: 'meet', meet: [{ name: 'Bruno Petit' }, { name: 'Chloé Durand' }] }) },
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
      handleGetApiCouncilRecoveryRequestsMine({ body: { request: request() } }),
      handlePostApiCouncilRecoveryRequestsByIdRefuse({ body: { refused: true } }),
    ],
  },
  encryption: {
    request: async (type: string, payload?: unknown) => (type === MSG_VAULT_COUNCIL_REQUEST_KEY ? null : defaultVaultRequest(type, payload)),
  },
};
OtherBrowserStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.other_browser'));
  await playFindButton(canvasElement, i18n.t('council.cancel_request'));
};
export const StartedFromAnotherBrowser = prepareStory(OtherBrowserStory);

const UnavailableStory = Template.bind({});
UnavailableStory.args = baseArgs;
UnavailableStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilRecoveryRequestsMine({ body: { request: null } }),
      handleGetApiCouncilsForMe({ body: forMe({ escrow: { health: { live: 1, threshold: 2, status: 'lost', outdated: false } } }) }),
    ],
  },
};
UnavailableStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.recovery_unavailable'));
};
export const Unavailable = prepareStory(UnavailableStory);

// Released: the shares are combined in this browser and the caller takes over.
const ReleasedStory = Template.bind({});
ReleasedStory.args = baseArgs;
ReleasedStory.parameters = {
  msw: {
    handlers: [
      handleGetApiCouncilRecoveryRequestsMine({ body: { request: request({ stage: 'released' }) } }),
      handleGetApiCouncilRecoveryRequestsByIdShares({
        body: {
          request_id: request().id,
          council_id: 'dinum',
          user_id: '00000000-0000-0000-0000-000000000000',
          generation: 1,
          threshold: 2,
          share_commitments: sampleCouncilEscrowRecord.share_commitments,
          lang: 'french',
          escrow: sampleCouncilEscrowRecord,
          contributions: [],
        },
      }),
    ],
  },
};
ReleasedStory.play = async ({ args }) => {
  await waitFor(() => expect(args.onRecovered).toHaveBeenCalledOnce());
};
export const Released = prepareStory(ReleasedStory);
