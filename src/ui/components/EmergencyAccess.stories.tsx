import { Meta, StoryFn } from '@storybook/react';
import { userEvent, within } from '@storybook/test';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindDialog } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import {
  handleGetApiEmergencyAccessGranted,
  handleGetApiEmergencyAccessSearch,
  handleGetApiEmergencyAccessTrusted,
  handlePostApiEmergencyAccess,
  handlePostApiEmergencyAccessByIdRecover,
} from '@encryption/src/ui/api/generated/msw.gen';
import type { GetApiEmergencyAccessGrantedResponses, GetApiEmergencyAccessTrustedResponses } from '@encryption/src/ui/api/generated/types.gen';
import { EmergencyAccess } from '@encryption/src/ui/components/EmergencyAccess';
import { sampleEmergencyEscrowRecord } from '@encryption/src/ui/testing/fixtures';

type TrustedContact = GetApiEmergencyAccessTrustedResponses[200]['contacts'][number];
type GrantedVault = GetApiEmergencyAccessGrantedResponses[200]['grantors'][number];

type ComponentType = typeof EmergencyAccess;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Modals/EmergencyAccess',
  component: EmergencyAccess,
  ...generateMetaDefault({ parameters: { layout: 'padded' } }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <EmergencyAccess {...args} />;

const baseArgs = {
  getToken: async () => 'mock-jwt-token',
  onClose: () => console.log('onClose'),
};

const DAY = 24 * 60 * 60 * 1000;

const trustedContact: TrustedContact = {
  id: '11111111-1111-1111-1111-111111111111',
  grantee_user_id: '22222222-2222-2222-2222-222222222222',
  grantee_email: 'bob.dupont@numerique.gouv.fr',
  status: 'confirmed' as const,
  wait_time_days: 15,
  created_at_millis: 1_700_000_000_000,
  recovery_requested_at_millis: null,
  deadline_millis: null,
  vault_active: true,
  escrow: sampleEmergencyEscrowRecord,
};

const grantedVault: GrantedVault = {
  id: '33333333-3333-3333-3333-333333333333',
  grantor_user_id: '44444444-4444-4444-4444-444444444444',
  grantor_email: 'carol.bernard@numerique.gouv.fr',
  status: 'confirmed' as const,
  wait_time_days: 30,
  created_at_millis: 1_700_000_000_000,
  recovery_requested_at_millis: null,
  deadline_millis: null,
};

// The two lists always load together; a story sets each to whatever its scenario needs.
function lists(contacts: TrustedContact[], grantors: GrantedVault[]) {
  return {
    handlers: [handleGetApiEmergencyAccessTrusted({ body: { contacts } }), handleGetApiEmergencyAccessGranted({ body: { grantors } })],
  };
}

const EmptyStory = Template.bind({});
EmptyStory.args = { ...baseArgs };
EmptyStory.parameters = { msw: lists([], []) };

export const Empty = prepareStory(EmptyStory);

const WithContactsStory = Template.bind({});
WithContactsStory.args = { ...baseArgs };
WithContactsStory.parameters = { msw: lists([trustedContact], []) };

export const WithContacts = prepareStory(WithContactsStory);

// A contact whose running request will auto-approve once the wait elapses: a
// live countdown, and the grantor's chance to refuse.
const RecoveryPendingStory = Template.bind({});
RecoveryPendingStory.args = { ...baseArgs };
RecoveryPendingStory.parameters = {
  msw: lists(
    [{ ...trustedContact, status: 'recoveryRequested', recovery_requested_at_millis: Date.now(), deadline_millis: Date.now() + 12 * DAY }],
    []
  ),
};

export const RecoveryPending = prepareStory(RecoveryPendingStory);

// The other side: a vault someone entrusted to me, which I can ask to recover.
const EntrustedToMeStory = Template.bind({});
EntrustedToMeStory.args = { ...baseArgs };
EntrustedToMeStory.parameters = { msw: lists([], [grantedVault]) };

export const EntrustedToMe = prepareStory(EntrustedToMeStory);

// The designation flow: search a colleague, land on the fingerprint-verify step
// (a designation is refused until the contact is verified out of band).
const DesignateStory = Template.bind({});
DesignateStory.args = { ...baseArgs };
DesignateStory.parameters = {
  msw: {
    handlers: [
      handleGetApiEmergencyAccessTrusted({ body: { contacts: [] } }),
      handleGetApiEmergencyAccessGranted({ body: { grantors: [] } }),
      handleGetApiEmergencyAccessSearch({
        body: { user: { user_id: '22222222-2222-2222-2222-222222222222', email: 'bob.dupont@numerique.gouv.fr' }, onboarded: true },
      }),
      handlePostApiEmergencyAccess({ body: { id: '11111111-1111-1111-1111-111111111111', status: 'invited' } }),
    ],
  },
};
DesignateStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('emergency.btn_designate')));
  const input = await within(canvasElement).findByRole('textbox');
  await userEvent.type(input, 'bob.dupont@numerique.gouv.fr');
  await userEvent.click(await playFindButton(canvasElement, i18n.t('emergency.btn_search')));
};

export const Designate = prepareStory(DesignateStory);

// The SDK auto-opened the interface on an actionable pending state. The signal
// is a bare boolean: the prompt's content (who, deadline, the id to refuse)
// comes from the component's own authenticated list, not from the signal.
const RecoveryPromptStory = Template.bind({});
RecoveryPromptStory.args = {
  ...baseArgs,
  emergencyPending: { recovery: true, invitation: false },
};
RecoveryPromptStory.parameters = {
  msw: lists(
    [{ ...trustedContact, status: 'recoveryRequested', recovery_requested_at_millis: Date.now(), deadline_millis: Date.now() + 12 * DAY }],
    []
  ),
};
// The prompt opens only after the authoritative list loads and confirms a
// running request, so assert the fetched contact's email and the refuse action
// surface (the modal renders in a portal on document.body).
RecoveryPromptStory.play = async () => {
  const dialog = await playFindDialog(document.body);
  await within(dialog).findByText(trustedContact.grantee_email);
  await playFindButton(dialog, i18n.t('emergency.btn_prompt_refuse'));
};

export const RecoveryPrompt = prepareStory(RecoveryPromptStory);

// ===========================================================================
// Grantee (contact) side — the full lifecycle of a vault entrusted to me.
// ===========================================================================

// Just designated me: I can accept the role or decline it.
const GrantedInvitedStory = Template.bind({});
GrantedInvitedStory.args = { ...baseArgs };
GrantedInvitedStory.parameters = { msw: lists([], [{ ...grantedVault, status: 'invited' }]) };
GrantedInvitedStory.play = async ({ canvasElement }) => {
  await playFindButton(canvasElement, i18n.t('emergency.btn_accept'));
  await playFindButton(canvasElement, i18n.t('emergency.btn_decline'));
};

export const GrantedInvited = prepareStory(GrantedInvitedStory);

// I requested a recovery: the wait is running and I can still cancel.
const GrantedRecoveryRequestedStory = Template.bind({});
GrantedRecoveryRequestedStory.args = { ...baseArgs };
GrantedRecoveryRequestedStory.parameters = {
  msw: lists(
    [],
    [{ ...grantedVault, status: 'recoveryRequested', recovery_requested_at_millis: Date.now(), deadline_millis: Date.now() + 20 * DAY }]
  ),
};
GrantedRecoveryRequestedStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(/requested emergency access/i);
  await playFindButton(canvasElement, i18n.t('emergency.btn_cancel_request'));
};

export const GrantedRecoveryRequested = prepareStory(GrantedRecoveryRequestedStory);

// The wait elapsed: I can now reveal the phrase to hand over in person.
const grantedApproved: GrantedVault = {
  ...grantedVault,
  status: 'recoveryApproved',
  recovery_requested_at_millis: Date.now() - 40 * DAY,
  deadline_millis: Date.now() - DAY,
};

const GrantedRecoveryApprovedStory = Template.bind({});
GrantedRecoveryApprovedStory.args = { ...baseArgs };
GrantedRecoveryApprovedStory.parameters = { msw: lists([], [grantedApproved]) };
GrantedRecoveryApprovedStory.play = async ({ canvasElement }) => {
  await playFindButton(canvasElement, i18n.t('emergency.btn_reveal'));
};

export const GrantedRecoveryApproved = prepareStory(GrantedRecoveryApprovedStory);

// The reveal screen itself: click through to the printable recovery phrase. The
// vault stub returns the phrase; the recover endpoint releases the capsule.
const recoverHandler = handlePostApiEmergencyAccessByIdRecover({
  body: {
    id: grantedApproved.id,
    grantor_user_id: grantedApproved.grantor_user_id,
    wait_time_days: grantedApproved.wait_time_days,
    lang: 'english',
    escrow: sampleEmergencyEscrowRecord,
  },
});

const RevealStory = Template.bind({});
RevealStory.args = { ...baseArgs };
RevealStory.parameters = {
  msw: {
    handlers: [
      handleGetApiEmergencyAccessTrusted({ body: { contacts: [] } }),
      handleGetApiEmergencyAccessGranted({ body: { grantors: [grantedApproved] } }),
      recoverHandler,
    ],
  },
};
RevealStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('emergency.btn_reveal')));
  await within(canvasElement).findByText(i18n.t('emergency.reveal_title'));
  await playFindButton(canvasElement, i18n.t('emergency.reveal_done'));
};

export const Reveal = prepareStory(RevealStory);

// Reveal blocked, fail-closed: the vault owner is not verified out of band, so
// the phrase is refused with a warning rather than shown.
const RevealUntrustedGrantorStory = Template.bind({});
RevealUntrustedGrantorStory.args = { ...baseArgs };
RevealUntrustedGrantorStory.parameters = {
  encryption: {
    revealEmergencyPhrase: async () => {
      throw new VaultError(VaultErrorCode.UNTRUSTED_RECIPIENT, 'grantor not verified');
    },
  },
  msw: {
    handlers: [
      handleGetApiEmergencyAccessTrusted({ body: { contacts: [] } }),
      handleGetApiEmergencyAccessGranted({ body: { grantors: [grantedApproved] } }),
      recoverHandler,
    ],
  },
};
RevealUntrustedGrantorStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('emergency.btn_reveal')));
  await within(canvasElement).findByText(/compare the safety code below/i);
  await playFindButton(canvasElement, i18n.t('emergency.btn_grantor_verified'));
};

export const RevealUntrustedGrantor = prepareStory(RevealUntrustedGrantorStory);

// ===========================================================================
// Grantor side — designated-but-not-accepted, and per-contact escrow audit.
// ===========================================================================

// A contact I designated who has not accepted the role yet.
const InvitedContactStory = Template.bind({});
InvitedContactStory.args = { ...baseArgs };
InvitedContactStory.parameters = { msw: lists([{ ...trustedContact, status: 'invited' }], []) };
InvitedContactStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('emergency.status_invited'));
  await playFindButton(canvasElement, i18n.t('emergency.btn_revoke'));
};

export const InvitedContact = prepareStory(InvitedContactStory);

// The escrow audit flags problems on SPECIFIC rows (it is keyed per contact):
// a tampered escrow (red), a changed identity (renew), an outdated key (re-arm).
// Proves the alerts are tied to the right person when several are listed.
const auditTampered: TrustedContact = {
  ...trustedContact,
  id: '55555555-5555-5555-5555-555555555555',
  grantee_email: 'alice.martin@numerique.gouv.fr',
};
const auditStale: TrustedContact = { ...trustedContact, id: '66666666-6666-6666-6666-666666666666', grantee_email: 'bruno.leroy@numerique.gouv.fr' };
const auditOutdated: TrustedContact = {
  ...trustedContact,
  id: '88888888-8888-8888-8888-888888888888',
  grantee_email: 'chloe.moreau@numerique.gouv.fr',
};

const AuditFailuresStory = Template.bind({});
AuditFailuresStory.args = { ...baseArgs };
AuditFailuresStory.parameters = {
  encryption: {
    verifyEscrows: async () => ({
      results: [
        { id: auditTampered.id, status: 'tampered' as const },
        { id: auditStale.id, status: 'stale-identity' as const },
        { id: auditOutdated.id, status: 'outdated-key' as const },
      ],
    }),
  },
  msw: lists([auditTampered, auditStale, auditOutdated], []),
};
AuditFailuresStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(/does not match what you signed/i);
  await within(canvasElement).findByText(/encryption identity has changed/i);
  await within(canvasElement).findByText(/encryption key has been updated/i);
};

export const AuditFailures = prepareStory(AuditFailuresStory);
