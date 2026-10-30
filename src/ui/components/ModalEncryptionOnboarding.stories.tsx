import { Meta, StoryFn } from '@storybook/react';
import { expect, fn, userEvent, waitFor, within } from 'storybook/test';

import { consoleFrame } from '@encryption/.storybook/figma';
import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { MSG_VAULT_COUNCIL_COMPLETE_RECOVERY } from '@encryption/src/shared/constants';
import { API_ERROR_VAULT_NOT_FOUND } from '@encryption/src/shared/error-codes';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import {
  handleGetApiCouncilRecoveryRequestsByIdShares,
  handleGetApiCouncilRecoveryRequestsMine,
  handleGetApiCouncilsForMe,
  handleGetApiEmergencyAccessTrusted,
  handleGetApiPublicKeys,
  handleGetApiPublicKeysNext,
  handleGetApiVaultMeta,
  handlePostApiCouncilRecoveryRequestsByIdRefuse,
  handlePostApiCouncilsEscrow,
  handlePostApiPublicKeysRegisterInit,
  handlePostApiVault,
} from '@encryption/src/ui/api/generated/msw.gen';
import { ModalEncryptionOnboarding } from '@encryption/src/ui/components/ModalEncryptionOnboarding';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { COUNCIL_LABEL, forMe } from '@encryption/src/ui/testing/council-stories';
import { sampleCouncilEscrowRecord, sampleEmergencyEscrowRecord, sampleFingerprint, samplePublicKey } from '@encryption/src/ui/testing/fixtures';
import { defaultVaultRequest } from '@encryption/src/ui/testing/mock-encryption';

type ComponentType = typeof ModalEncryptionOnboarding;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Pages/EncryptionOnboarding',
  component: ModalEncryptionOnboarding,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: true,
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => {
  return <ModalEncryptionOnboarding {...args} />;
};

const NewUserStory = Template.bind({});
NewUserStory.args = {
  getIdToken: async () => 'mock-jwt-token',
  userId: '00000000-0000-0000-0000-000000000000',
  onClose: () => console.log('onClose'),
  onSuccess: (pk) => console.log('onSuccess', pk),
  onUseAnotherDevice: () => console.log('onUseAnotherDevice'),
  onOpenEmergencyAccess: () => console.log('onOpenEmergencyAccess'),
  onStepUp: () => console.log('onStepUp'),
  hasExistingBackendKey: false,
};
const newUserHandlers = [
  handleGetApiPublicKeys({ body: { keys: [] } }),
  handleGetApiPublicKeysNext({ body: { next_version: 1, next_generation: 1 } }),
  handleGetApiVaultMeta(() => Response.json({ code: API_ERROR_VAULT_NOT_FOUND }, { status: 404 })),
];
NewUserStory.parameters = {
  msw: { handlers: newUserHandlers },
};
NewUserStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_enable'));
};

NewUserStory.parameters = { ...NewUserStory.parameters, design: consoleFrame('4879-12692') };
export const NewUser = prepareStory(NewUserStory);

const ExistingUserStory = Template.bind({});
ExistingUserStory.args = {
  getIdToken: async () => 'mock-jwt-token',
  userId: '00000000-0000-0000-0000-000000000000',
  onClose: () => console.log('onClose'),
  onSuccess: (pk) => console.log('onSuccess', pk),
  onUseAnotherDevice: () => console.log('onUseAnotherDevice'),
  onOpenEmergencyAccess: () => console.log('onOpenEmergencyAccess'),
  onStepUp: () => console.log('onStepUp'),
  hasExistingBackendKey: true,
  userInfo: { name: 'Alice Martin', email: 'alice.martin@numerique.gouv.fr' },
};
ExistingUserStory.parameters = {
  msw: {
    handlers: [
      handleGetApiPublicKeys(({ request }) => {
        const userIds = new URL(request.url).searchParams.getAll('user_ids');

        return Response.json({ keys: userIds.map((user_id) => ({ ...samplePublicKey, user_id })) });
      }),
    ],
  },
};
ExistingUserStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_existing'));
  // Two ways back, as selectable cards: another device first, then the phrase.
  const device = await within(canvasElement).findByRole('radio', { name: new RegExp(i18n.t('onboarding.btn_use_another_device')) });
  const phrase = await within(canvasElement).findByRole('radio', { name: new RegExp(i18n.t('onboarding.btn_restore_from_backup')) });
  await expect(device).toBeChecked();
  // One tab stop, arrow keys between the cards.
  device.focus();
  await userEvent.keyboard('{ArrowDown}');
  await expect(phrase).toBeChecked();
  await expect(phrase).toHaveFocus();
  await playFindButton(canvasElement, i18n.t('onboarding.btn_continue'));
};

ExistingUserStory.parameters = { ...ExistingUserStory.parameters, design: consoleFrame('4880-17085') };
export const ExistingUser = prepareStory(ExistingUserStory);

// Covered by a recovery council that can still help: a third way back, next to
// another device and the recovery phrase (which a trusted contact hands back).
const ExistingUserWithCouncilStory = Template.bind({});
ExistingUserWithCouncilStory.args = { ...ExistingUserStory.args };
ExistingUserWithCouncilStory.parameters = {
  msw: {
    handlers: [
      handleGetApiPublicKeys(({ request }) => {
        const userIds = new URL(request.url).searchParams.getAll('user_ids');

        return Response.json({ keys: userIds.map((user_id) => ({ ...samplePublicKey, user_id })) });
      }),
      handleGetApiCouncilsForMe({ body: forMe({ escrow: {} }) }),
      // So that Continue opens the council's first screen.
      handleGetApiCouncilRecoveryRequestsMine({ body: { request: null } }),
    ],
  },
};
ExistingUserWithCouncilStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_existing'));
  const canvas = within(canvasElement);
  await canvas.findByRole('radio', { name: new RegExp(i18n.t('onboarding.btn_use_another_device')) });
  await canvas.findByRole('radio', { name: new RegExp(i18n.t('onboarding.btn_restore_from_backup')) });
  const council = await canvas.findByRole('radio', { name: new RegExp(i18n.t('council.option_title')) });
  await userEvent.click(council);
  await expect(council).toBeChecked();
};
export const ExistingUserWithCouncil = prepareStory(ExistingUserWithCouncilStory);

// The council released the shares: the vault opens in this browser, then the
// forced phrase change cannot be prepared. The user lands on a screen that
// resumes it, never on a spinner.
const COUNCIL_REQUEST_ID = '5d6e7f80-0000-4000-8000-000000000001';
const councilReleasedHandlers = [
  handleGetApiPublicKeys(({ request }) => {
    const userIds = new URL(request.url).searchParams.getAll('user_ids');

    return Response.json({ keys: userIds.map((user_id) => ({ ...samplePublicKey, user_id })) });
  }),
  handleGetApiCouncilsForMe({ body: forMe({ escrow: {} }) }),
  handleGetApiCouncilRecoveryRequestsMine({
    body: {
      request: {
        id: COUNCIL_REQUEST_ID,
        council_label: COUNCIL_LABEL,
        stage: 'released',
        ephemeral_fingerprint: sampleFingerprint,
        created_at_millis: Date.UTC(2026, 9, 28, 9),
        expires_at_millis: Date.UTC(2026, 10, 4, 9),
        meet: [],
        vault_active: true,
        vault_created_at_millis: Date.UTC(2026, 0, 12),
      },
    },
  }),
  handleGetApiCouncilRecoveryRequestsByIdShares({
    body: {
      request_id: COUNCIL_REQUEST_ID,
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
];

async function chooseCouncil(canvasElement: HTMLElement) {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_existing'));
  await userEvent.click(await within(canvasElement).findByRole('radio', { name: new RegExp(i18n.t('council.option_title')) }));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
}

// The usual case: the council gave back the vault the user still has, so the
// next screen is the new recovery phrase, which burns the one the council released.
const CouncilNewPhraseStory = Template.bind({});
CouncilNewPhraseStory.args = { ...ExistingUserStory.args };
CouncilNewPhraseStory.parameters = { msw: { handlers: councilReleasedHandlers } };
CouncilNewPhraseStory.play = async ({ canvasElement }) => {
  await chooseCouncil(canvasElement);
  await playFindHeading(canvasElement, i18n.t('emergency.rotation_title'));
  await within(canvasElement).findByText(i18n.t('council.rotation_explanation'));
};
export const CouncilRecoveryNewPhrase = prepareStory(CouncilNewPhraseStory);

const CouncilRotationFailedStory = Template.bind({});
CouncilRotationFailedStory.args = { ...ExistingUserStory.args };
CouncilRotationFailedStory.parameters = {
  msw: { handlers: councilReleasedHandlers },
  encryption: {
    changeRecoveryPhrase: async () => {
      throw new VaultError(VaultErrorCode.TIMEOUT, 'vault request timed out');
    },
  },
};
CouncilRotationFailedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await chooseCouncil(canvasElement);
  await playFindHeading(canvasElement, i18n.t('council.unfinished_title'));
  await canvas.findByText(i18n.t('errors.vault.request_timeout'));
  // Resuming tries again, and lands on the same screen while it keeps failing.
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await playFindHeading(canvasElement, i18n.t('council.unfinished_title'));
  await canvas.findByText(i18n.t('errors.vault.request_timeout'));
};
export const CouncilRecoveryRotationFailed = prepareStory(CouncilRotationFailedStory);

// Rare: after losing access the user created a new vault, then asked the council
// for the older one. Bringing it back is confirmed; keeping the current vault
// instead closes the request, which is confirmed too.
const olderVaultRecovered = async (type: string, payload?: unknown) =>
  type === MSG_VAULT_COUNCIL_COMPLETE_RECOVERY
    ? {
        publicKey: samplePublicKey.encryption_public_key,
        signaturePublicKey: samplePublicKey.signature_public_key,
        isActiveVault: false,
        vaultCreatedAtMillis: Date.UTC(2025, 2, 1),
        contributors: [],
      }
    : defaultVaultRequest(type, payload);

const CouncilKeepCurrentVaultStory = Template.bind({});
CouncilKeepCurrentVaultStory.args = { ...ExistingUserStory.args };
CouncilKeepCurrentVaultStory.parameters = {
  msw: { handlers: councilReleasedHandlers },
  encryption: { request: olderVaultRecovered },
};
CouncilKeepCurrentVaultStory.play = async ({ canvasElement }) => {
  await chooseCouncil(canvasElement);
  const body = within(canvasElement.ownerDocument.body);
  // The request's date first, so the person recognizes what they asked for.
  await body.findByText(i18n.t('council.reactivate_requested', { date: new Date(Date.UTC(2026, 9, 28, 9)) }));
  await body.findByRole('button', { name: i18n.t('council.reactivate_confirm_button') });
  await userEvent.click(await body.findByRole('button', { name: i18n.t('council.keep_current_button') }));
  await body.findByText(i18n.t('council.keep_current_body'));
  await body.findByRole('button', { name: i18n.t('council.keep_current_confirm') });
};
export const CouncilRecoveryKeepCurrentVault = prepareStory(CouncilKeepCurrentVaultStory);

// Confirmed: the request is closed. This browser never held the current vault
// (the council is only offered without one), so it is back to the ways to
// restore it, and says so.
const refused = fn();
const CouncilKeptCurrentVaultStory = Template.bind({});
CouncilKeptCurrentVaultStory.args = { ...ExistingUserStory.args };
CouncilKeptCurrentVaultStory.parameters = {
  msw: {
    handlers: [
      ...councilReleasedHandlers,
      handlePostApiCouncilRecoveryRequestsByIdRefuse(({ params }) => {
        refused(params.id);

        return Response.json({ refused: true });
      }),
    ],
  },
  encryption: { request: olderVaultRecovered },
};
CouncilKeptCurrentVaultStory.play = async ({ canvasElement }) => {
  refused.mockClear();
  await chooseCouncil(canvasElement);
  const body = within(canvasElement.ownerDocument.body);
  await userEvent.click(await body.findByRole('button', { name: i18n.t('council.keep_current_button') }));
  await userEvent.click(await body.findByRole('button', { name: i18n.t('council.keep_current_confirm') }));
  await playFindHeading(canvasElement, i18n.t('onboarding.title_existing'));
  // This browser never held the current vault: it still has to be restored here.
  await within(canvasElement).findByText(i18n.t('council.kept_current_notice'));
  await waitFor(() => expect(refused).toHaveBeenCalledWith(COUNCIL_REQUEST_ID));
};
export const CouncilRecoveryKeptCurrentVault = prepareStory(CouncilKeptCurrentVaultStory);

// This browser already holds the vault in use (created after the request): the
// settings open the council's request, and the question says so.
const CouncilOlderVaultHereStory = Template.bind({});
CouncilOlderVaultHereStory.args = { ...ExistingUserStory.args, councilForOlderVault: true };
CouncilOlderVaultHereStory.parameters = {
  msw: { handlers: councilReleasedHandlers },
  encryption: { request: olderVaultRecovered },
};
CouncilOlderVaultHereStory.play = async ({ canvasElement }) => {
  const body = within(canvasElement.ownerDocument.body);
  await body.findByText(i18n.t('council.reactivate_confirm_here', { date: new Date(Date.UTC(2025, 2, 1)), active: new Date(Date.UTC(2026, 0, 12)) }));
  await userEvent.click(await body.findByRole('button', { name: i18n.t('council.keep_current_button') }));
  await body.findByText(i18n.t('council.keep_current_body_here'));
};
export const CouncilRecoveryOlderVaultHere = prepareStory(CouncilOlderVaultHereStory);

// This browser held the vault but forgot it after a year without use: the same
// choice, explained.
const ExistingUserDeEnrolledStory = Template.bind({});
ExistingUserDeEnrolledStory.args = { ...ExistingUserStory.args };
ExistingUserDeEnrolledStory.parameters = {
  ...ExistingUserStory.parameters,
  encryption: {
    ...ExistingUserStory.parameters?.encryption,
    hasKeys: async () => ({ hasKeys: false, deEnrolled: { deEnrolledAt: 1_750_000_000_000, inactivityDays: 365 } }),
  },
};
ExistingUserDeEnrolledStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_existing'));
  await waitFor(() => expect(canvasElement.textContent).toContain(i18n.t('onboarding.de_enrolled_notice', { count: 365 })));
};

export const ExistingUserDeEnrolled = prepareStory(ExistingUserDeEnrolledStory);

// No ACTIVE key, but a dormant vault: the account registered before and was reset.
const PreviousIdentityStory = Template.bind({});
PreviousIdentityStory.args = {
  ...NewUserStory.args,
};
const previousIdentityHandlers = [
  handleGetApiPublicKeys({ body: { keys: [] } }),
  handleGetApiPublicKeysNext({ body: { next_version: 3, next_generation: 2 } }),
  handleGetApiVaultMeta({ body: { kdf_variants: [{ kdf_ops: 3, kdf_mem: 67108864 }] } }),
];
PreviousIdentityStory.parameters = { msw: { handlers: previousIdentityHandlers } };
PreviousIdentityStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_previous_identity'));
  // The trusted-contacts request answers 501 here: no sentence about contacts.
  expect(canvasElement.textContent).not.toContain('@');
};

export const PreviousIdentity = prepareStory(PreviousIdentityStory);

// The same history, seen from a browser that also forgot its vault after a year
// without use (the identity was reset from another device meanwhile): explained too.
const PreviousIdentityDeEnrolledStory = Template.bind({});
PreviousIdentityDeEnrolledStory.args = { ...PreviousIdentityStory.args };
PreviousIdentityDeEnrolledStory.parameters = {
  ...PreviousIdentityStory.parameters,
  encryption: {
    ...PreviousIdentityStory.parameters?.encryption,
    hasKeys: async () => ({ hasKeys: false, deEnrolled: { deEnrolledAt: 1_750_000_000_000, inactivityDays: 365 } }),
  },
};
PreviousIdentityDeEnrolledStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_previous_identity'));
  await waitFor(() => expect(canvasElement.textContent).toContain(i18n.t('onboarding.de_enrolled_notice', { count: 365 })));
};

export const PreviousIdentityDeEnrolled = prepareStory(PreviousIdentityDeEnrolledStory);

// Registered before, but every dormant vault was deleted by the retention job: no
// phrase can restore anything, so the fresh start is offered directly.
const PurgedHistoryStory = Template.bind({});
PurgedHistoryStory.args = { ...NewUserStory.args };
PurgedHistoryStory.parameters = {
  msw: {
    handlers: [
      handleGetApiPublicKeys({ body: { keys: [] } }),
      handleGetApiPublicKeysNext({ body: { next_version: 3, next_generation: 2 } }),
      handleGetApiVaultMeta(() => Response.json({ code: API_ERROR_VAULT_NOT_FOUND }, { status: 404 })),
    ],
  },
};
PurgedHistoryStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_enable'));
  expect(canvasElement.textContent).not.toContain(i18n.t('onboarding.title_previous_identity'));
};

export const PurgedHistory = prepareStory(PurgedHistoryStory);

// Same history, but the account had designated trusted contacts before the
// identity was disabled: the screen names them as a way back in. An invitation
// that was never accepted is not one, so the pending contact stays out.
const trustedContact = (id: string, name: string, email: string, status: 'confirmed' | 'invited') => ({
  id,
  grantee_user_id: '22222222-2222-2222-2222-222222222222',
  grantee_email: email,
  grantee_name: name,
  status,
  wait_time_days: 15,
  created_at_millis: 1_700_000_000_000,
  recovery_requested_at_millis: null,
  deadline_millis: null,
  vault_active: false,
  escrow: sampleEmergencyEscrowRecord,
});

const PreviousIdentityWithContactsStory = Template.bind({});
PreviousIdentityWithContactsStory.args = { ...NewUserStory.args };
PreviousIdentityWithContactsStory.parameters = {
  msw: {
    handlers: [
      ...previousIdentityHandlers,
      handleGetApiEmergencyAccessTrusted({
        body: {
          contacts: [
            trustedContact('11111111-1111-1111-1111-111111111111', 'Bob Dupont', 'bob.dupont@numerique.gouv.fr', 'confirmed'),
            trustedContact('11111111-1111-1111-1111-111111111112', 'Carol Bernard', 'carol.bernard@numerique.gouv.fr', 'confirmed'),
            trustedContact('11111111-1111-1111-1111-111111111113', 'Dan Martin', 'dan.martin@numerique.gouv.fr', 'invited'),
          ],
        },
      }),
    ],
  },
};
PreviousIdentityWithContactsStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('onboarding.title_previous_identity'));
  // Each contact by name, the email under it.
  await waitFor(() => expect(canvasElement.textContent).toContain('Bob Dupont'));
  expect(canvasElement.textContent).toContain('bob.dupont@numerique.gouv.fr');
  expect(canvasElement.textContent).toContain('Carol Bernard');
  expect(canvasElement.textContent).not.toContain('Dan Martin');
};

export const PreviousIdentityWithContacts = prepareStory(PreviousIdentityWithContactsStory);

// Internal state, no prop to set it: the click is the only way in.
const RestoreStory = Template.bind({});
RestoreStory.args = { ...ExistingUserStory.args };
RestoreStory.parameters = ExistingUserStory.parameters;
RestoreStory.play = async ({ canvasElement }) => {
  await userEvent.click(await within(canvasElement).findByRole('radio', { name: new RegExp(i18n.t('onboarding.btn_restore_from_backup')) }));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await playFindHeading(canvasElement, i18n.t('onboarding.title_restore'));
};

RestoreStory.parameters = { ...RestoreStory.parameters, design: consoleFrame('4880-17087') };
export const Restore = prepareStory(RestoreStory);

// 24 words of the English list, pasted at once like a saved sheet.
const PASTED_PHRASE = Array.from({ length: 24 }, () => 'abandon').join(' ');

async function playSubmitPhrase(canvasElement: HTMLElement) {
  await userEvent.click(await within(canvasElement).findByRole('radio', { name: new RegExp(i18n.t('onboarding.btn_restore_from_backup')) }));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await userEvent.click(await within(canvasElement).findByLabelText('Word 1'));
  await userEvent.paste(PASTED_PHRASE);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_restore')));
}

// The phrase opened nothing: every box turns red, the reason sits under them,
// and the button waits for an edit.
const RestoreRejectedStory = Template.bind({});
RestoreRejectedStory.args = { ...ExistingUserStory.args };
RestoreRejectedStory.parameters = {
  ...ExistingUserStory.parameters,
  encryption: {
    restoreFromPhrase: async () => {
      throw new VaultError(VaultErrorCode.WRONG_SECRET_KEY, 'wrong phrase');
    },
  },
};
RestoreRejectedStory.play = async ({ canvasElement }) => {
  await playSubmitPhrase(canvasElement);
  await within(canvasElement).findByText(i18n.t('errors.vault.wrong_recovery_phrase'));
  await expect(await playFindButton(canvasElement, i18n.t('onboarding.btn_restore'))).toBeDisabled();
};

RestoreRejectedStory.parameters = { ...RestoreRejectedStory.parameters, design: consoleFrame('4884-27719') };
export const RestoreRejected = prepareStory(RestoreRejectedStory);

const RestoredStory = Template.bind({});
RestoredStory.args = { ...ExistingUserStory.args };
RestoredStory.parameters = ExistingUserStory.parameters;
RestoredStory.play = async ({ canvasElement }) => {
  await playSubmitPhrase(canvasElement);
  await playFindHeading(canvasElement, i18n.t('onboarding.title_enabled'));
  await within(canvasElement).findByText(i18n.t('onboarding.restored_description'));
};

RestoredStory.parameters = { ...RestoredStory.parameters, design: consoleFrame('4882-22604') };
export const Restored = prepareStory(RestoredStory);

// Back in with the phrase while the council worked on a request for this vault:
// the server closed it, and the user is told here.
const RestoredCouncilClosedStory = Template.bind({});
RestoredCouncilClosedStory.args = { ...ExistingUserStory.args };
RestoredCouncilClosedStory.parameters = {
  ...ExistingUserStory.parameters,
  encryption: {
    restoreFromPhrase: async () => ({
      publicKey: samplePublicKey.encryption_public_key,
      signaturePublicKey: samplePublicKey.signature_public_key,
      isActiveVault: true,
      vaultCreatedAtMillis: samplePublicKey.created_at_millis,
      emergencyUnlock: false,
      councilRequestClosed: true,
    }),
  },
};
RestoredCouncilClosedStory.play = async ({ canvasElement }) => {
  await playSubmitPhrase(canvasElement);
  const body = within(canvasElement.ownerDocument.body);
  await body.findByText(i18n.t('council.closed_body'));
  await body.findByRole('button', { name: i18n.t('council.closed_ok') });
  // Over the usual end of the restore, which stays.
  await within(canvasElement).findByText(i18n.t('onboarding.restored_description'));
};
export const RestoredCouncilRequestClosed = prepareStory(RestoredCouncilClosedStory);

const LastResortStory = Template.bind({});
LastResortStory.args = { ...ExistingUserStory.args };
// No frame of its own in the design: the existing user's mocks without their link.
LastResortStory.parameters = { msw: ExistingUserStory.parameters.msw };
LastResortStory.play = async ({ canvasElement }) => {
  // "Lost phrase?" sits under the phrase boxes.
  await userEvent.click(await within(canvasElement).findByRole('radio', { name: new RegExp(i18n.t('onboarding.btn_restore_from_backup')) }));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_last_resort')));
  await playFindHeading(canvasElement, i18n.t('onboarding.title_last_resort'));
  // Confirmed like turning encryption off: the "I understand" tick alone unlocks it.
  const reset = await playFindButton(canvasElement, i18n.t('onboarding.btn_confirm_reset'));
  await expect(reset).toBeDisabled();
  await playFindButton(canvasElement, i18n.t('onboarding.btn_cancel'));
  await userEvent.click(within(canvasElement).getByRole('checkbox', { name: i18n.t('onboarding.i_understand') }));
  await expect(reset).toBeEnabled();
};

export const LastResort = prepareStory(LastResortStory);

// Starting over while a request to the council runs: it carries on for the vault replaced.
const LastResortCouncilStory = Template.bind({});
LastResortCouncilStory.args = { ...ExistingUserStory.args };
LastResortCouncilStory.parameters = {
  msw: {
    handlers: [
      handleGetApiPublicKeys(({ request }) => {
        const userIds = new URL(request.url).searchParams.getAll('user_ids');

        return Response.json({ keys: userIds.map((user_id) => ({ ...samplePublicKey, user_id })) });
      }),
      handleGetApiCouncilRecoveryRequestsMine({
        body: {
          request: {
            id: COUNCIL_REQUEST_ID,
            council_label: COUNCIL_LABEL,
            stage: 'meet',
            ephemeral_fingerprint: sampleFingerprint,
            created_at_millis: Date.UTC(2026, 9, 28, 9),
            expires_at_millis: Date.UTC(2026, 10, 4, 9),
            meet: [],
            vault_active: true,
            vault_created_at_millis: Date.UTC(2026, 0, 12),
          },
        },
      }),
    ],
  },
};
LastResortCouncilStory.play = async ({ canvasElement }) => {
  await userEvent.click(await within(canvasElement).findByRole('radio', { name: new RegExp(i18n.t('onboarding.btn_restore_from_backup')) }));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_last_resort')));
  await within(canvasElement).findByText(i18n.t('council.last_resort_request_open'));
};
export const LastResortWithCouncilRequest = prepareStory(LastResortCouncilStory);

// The recovery phrase step: the keys are minted locally and the confirmation
// stays locked until the phrase left the screen one way or another.
const BackupStory = Template.bind({});
BackupStory.args = { ...NewUserStory.args };
BackupStory.parameters = NewUserStory.parameters;
BackupStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await playFindHeading(canvasElement, i18n.t('onboarding.title_backup'));

  // Hidden until asked for, and nothing to confirm before the phrase left the screen.
  expect(await playFindButton(canvasElement, i18n.t('onboarding.btn_backup_done'))).toBeDisabled();
  await playFindButton(canvasElement, i18n.t('onboarding.btn_reveal'));
  expect(canvasElement.querySelector(`.${styles.words}`)).toBeNull();
};

BackupStory.parameters = { ...BackupStory.parameters, design: consoleFrame('4879-12693') };
export const Backup = prepareStory(BackupStory);

// Covered by a council: once the phrase is saved and the vault created, one
// more step offers to join it, and the last screen names it.
const NewUserJoinsCouncilStory = Template.bind({});
NewUserJoinsCouncilStory.args = { ...NewUserStory.args };
NewUserJoinsCouncilStory.parameters = {
  msw: {
    handlers: [
      ...newUserHandlers,
      handlePostApiPublicKeysRegisterInit({ body: { challenge_id: '7f1c2b3a-0000-4000-8000-00000000000a', ciphertext: 'Y2lwaGVydGV4dA' } }),
      handlePostApiVault({ body: { revision: 1 } }),
      handleGetApiCouncilsForMe({ body: forMe() }),
      handlePostApiCouncilsEscrow({ body: { id: '7f1c2b3a-0000-4000-8000-000000000001' } }),
    ],
  },
};
NewUserJoinsCouncilStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_reveal')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_backup_done')));

  await playFindHeading(canvasElement, i18n.t('council.join_title'));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.join_button')));

  await playFindHeading(canvasElement, i18n.t('onboarding.title_enabled'));
  await within(canvasElement).findByText(i18n.t('council.onboarding_joined', { council: COUNCIL_LABEL }));
};
export const NewUserJoinsCouncil = prepareStory(NewUserJoinsCouncilStory);

// Nothing to join: straight to the last screen.
const NewUserWithoutCouncilStory = Template.bind({});
NewUserWithoutCouncilStory.args = { ...NewUserStory.args };
NewUserWithoutCouncilStory.parameters = {
  msw: {
    handlers: [
      ...newUserHandlers,
      handlePostApiPublicKeysRegisterInit({ body: { challenge_id: '7f1c2b3a-0000-4000-8000-00000000000a', ciphertext: 'Y2lwaGVydGV4dA' } }),
      handlePostApiVault({ body: { revision: 1 } }),
      handleGetApiCouncilsForMe({ body: { council: null, escrow: null, active_vault_created_at_millis: null, vaults: [] } }),
    ],
  },
};
NewUserWithoutCouncilStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_reveal')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_backup_done')));

  await playFindHeading(canvasElement, i18n.t('onboarding.title_enabled'));
  expect(within(canvasElement).queryByText(i18n.t('council.onboarding_joined', { council: COUNCIL_LABEL }))).toBeNull();
};
export const NewUserWithoutCouncil = prepareStory(NewUserWithoutCouncilStory);

// The product's cross on the backup step does not close: the screen holds a
// guard that asks first. The story ends with the prompt open, which is the
// state it shows; "go back" and "close anyway" are exercised by hand, since
// driving them here would open and close the prompt in front of the viewer.
const BackupCancelPromptStory = Template.bind({});
BackupCancelPromptStory.args = { ...NewUserStory.args };
BackupCancelPromptStory.parameters = NewUserStory.parameters;
BackupCancelPromptStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await playFindHeading(canvasElement, i18n.t('onboarding.title_backup'));
  await userEvent.click(await playFindButton(canvasElement, 'Close'));
  await playFindHeading(document.body, i18n.t('onboarding.cancel_setup_title'));
};

BackupCancelPromptStory.parameters = { ...BackupCancelPromptStory.parameters, design: consoleFrame('4879-12695') };
export const BackupCancelPrompt = prepareStory(BackupCancelPromptStory);

// Replacing an identity the account already has (here a disabled one, so the
// user starts over): the server asks for a fresh second-factor sign-in (RFC 9470
// step-up) before issuing the registration challenge. It is checked at the
// commit, after the phrase is saved, because the fresh sign-in only counts for a
// few minutes. It then takes the place of the backup screen; the phrase stays
// valid, and the commit runs again once it is confirmed.
const StepUpRequiredStory = Template.bind({});
StepUpRequiredStory.args = { ...PreviousIdentityStory.args, onStepUp: fn() };
StepUpRequiredStory.parameters = {
  msw: {
    handlers: [
      ...previousIdentityHandlers,
      handlePostApiPublicKeysRegisterInit(
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
StepUpRequiredStory.play = async ({ canvasElement, args }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_start_new_identity')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_continue')));
  await playFindHeading(canvasElement, i18n.t('onboarding.title_backup'));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_reveal')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_backup_done')));

  // The step-up replaces the backup screen: nothing else to do until it is confirmed.
  await playFindHeading(canvasElement, i18n.t('auth.step_up_title'));
  expect(within(canvasElement).queryByRole('button', { name: i18n.t('onboarding.btn_copy_clipboard') })).toBeNull();

  await userEvent.click(await playFindButton(canvasElement, i18n.t('auth.step_up_confirm')));
  expect(args.onStepUp).toHaveBeenCalled();
};

export const StepUpRequired = prepareStory(StepUpRequiredStory);
