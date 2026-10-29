import { Meta, StoryFn } from '@storybook/react';
import { expect, fn, userEvent, within } from 'storybook/test';

import { consoleFrame } from '@encryption/.storybook/figma';
import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import {
  handleDeleteApiEmergencyAccessById,
  handleGetApiCouncilsForMe,
  handleGetApiCouncilsMine,
  handleGetApiEmergencyAccessTrusted,
  handleGetApiPublicKeys,
  handleGetApiPublicKeysNext,
} from '@encryption/src/ui/api/generated/msw.gen';
import { EncryptionSettings } from '@encryption/src/ui/components/EncryptionSettings';
import { custodianCouncil, forMe, vaultCheckingEscrow } from '@encryption/src/ui/testing/council-stories';
import { sampleEmergencyEscrowRecord, samplePublicKey } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof EncryptionSettings;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Pages/EncryptionSettings',
  component: EncryptionSettings,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: true,
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <EncryptionSettings {...args} />;

const DEMO_USER_ID = '00000000-0000-0000-0000-000000000000';

const baseArgs = {
  getIdToken: async () => 'mock-jwt-token',
  userId: DEMO_USER_ID,
  userInfo: { name: 'Alice Martin', email: 'alice.martin@numerique.gouv.fr' },
  onClose: () => console.log('onClose'),
  onKeysDestroyed: () => console.log('onKeysDestroyed'),
  onSetUp: () => console.log('onSetUp'),
  // The app always wires both sub-flows; without them the home shows fewer actions.
  onOpenDeviceApproval: () => console.log('onOpenDeviceApproval'),
  onOpenEmergencyAccess: () => console.log('onOpenEmergencyAccess'),
};

const directoryInSync = handleGetApiPublicKeys({ body: { keys: [{ ...samplePublicKey, user_id: DEMO_USER_ID }] } });
// `next_generation > 1` proves a registration existed, so re-enabling is legitimate.
const directoryDisabled = [
  handleGetApiPublicKeys({ body: { keys: [] } }),
  handleGetApiPublicKeysNext({ body: { next_version: 2, next_generation: 2 } }),
];
// `next_generation === 1`: nothing was ever registered, so the local keys are orphaned.
const directoryNeverRegistered = [
  handleGetApiPublicKeys({ body: { keys: [] } }),
  handleGetApiPublicKeysNext({ body: { next_version: 1, next_generation: 1 } }),
];
// The directory returns a DIFFERENT signature key from the one the vault stub holds.
const directoryDiverged = handleGetApiPublicKeys({
  body: {
    keys: [{ ...samplePublicKey, user_id: DEMO_USER_ID, signature_public_key: `B${samplePublicKey.signature_public_key.slice(1)}` }],
  },
});

// The interface's own encryption home, for a product without an account page.
const HomeStory = Template.bind({});
HomeStory.args = { ...baseArgs };
HomeStory.parameters = {
  msw: { handlers: [directoryInSync] },
};
HomeStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('settings.title'));
  await within(canvasElement).findByText(i18n.t('settings.status_active'));
  await playFindButton(canvasElement, i18n.t('settings.add_device'));
  await playFindButton(canvasElement, i18n.t('settings.show_code'));
  await playFindButton(canvasElement, i18n.t('settings.change_phrase'));
  await playFindButton(canvasElement, i18n.t('settings.manage_trusted_contacts'));
};

HomeStory.parameters = { ...HomeStory.parameters, design: consoleFrame('4905-9065') };
export const Home = prepareStory(HomeStory);

// Covered by a recovery council, and custodian of one with a request waiting.
const HomeWithCouncilStory = Template.bind({});
HomeWithCouncilStory.args = {
  ...baseArgs,
  onOpenRecoveryCouncil: () => console.log('onOpenRecoveryCouncil'),
  onOpenCustodian: () => console.log('onOpenCustodian'),
};
HomeWithCouncilStory.parameters = {
  msw: {
    handlers: [
      directoryInSync,
      handleGetApiCouncilsForMe({ body: forMe({ escrow: {} }) }),
      handleGetApiCouncilsMine({
        body: {
          mfa_enforced: true,
          councils: [
            custodianCouncil({
              requests: [
                {
                  id: '5d6e7f80-0000-4000-8000-000000000001',
                  user_name: 'Ursula Roux',
                  user_email: 'ursula.roux@numerique.gouv.fr',
                  created_at_millis: 1_760_000_000_000,
                  expires_at_millis: 1_760_600_000_000,
                  stage: 'collecting',
                  contributors: [], threshold: 2,
                  my_contribution: 'none',
                  can_contribute: true,
                },
              ],
            }),
          ],
        },
      }),
    ],
  },
};
HomeWithCouncilStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.row_title'));
  await canvas.findByText(i18n.t('council.custodian_row_pending', { count: 1 }));
  expect(canvas.getAllByRole('button', { name: i18n.t('council.row_open') })).toHaveLength(1);
  // Joined without verifying: the row says so.
  await canvas.findByText(i18n.t('council.chip_unverified'));
};
export const HomeWithCouncil = prepareStory(HomeWithCouncilStory);

// An unverified council: the row offers its verification rather than opening the council.
const HomeCouncilUnverifiedStory = Template.bind({});
HomeCouncilUnverifiedStory.args = {
  ...HomeWithCouncilStory.args,
  onVerifyRecoveryCouncil: fn(),
};
HomeCouncilUnverifiedStory.parameters = HomeWithCouncilStory.parameters;
HomeCouncilUnverifiedStory.play = async ({ canvasElement, args }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.chip_unverified'));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.verify_open')));
  expect(args.onVerifyRecoveryCouncil).toHaveBeenCalledOnce();
  expect(canvas.queryByRole('button', { name: i18n.t('council.row_open') })).toBeNull();
};
export const HomeCouncilUnverified = prepareStory(HomeCouncilUnverifiedStory);

const HomeCouncilVerifiedStory = Template.bind({});
HomeCouncilVerifiedStory.args = HomeCouncilUnverifiedStory.args;
HomeCouncilVerifiedStory.parameters = { ...HomeWithCouncilStory.parameters, encryption: { request: vaultCheckingEscrow('ok', true) } };
HomeCouncilVerifiedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.chip_verified'));
  expect(canvas.queryByRole('button', { name: i18n.t('council.verify_open') })).toBeNull();
  canvas.getByRole('button', { name: i18n.t('council.row_open') });
};
export const HomeCouncilVerified = prepareStory(HomeCouncilVerifiedStory);

// From the home, a flow comes back to it; the story ends on the flow, opened again.
const HomeToVerificationCodeStory = Template.bind({});
HomeToVerificationCodeStory.args = { ...baseArgs };
HomeToVerificationCodeStory.parameters = HomeStory.parameters;
HomeToVerificationCodeStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('settings.show_code')));
  await playFindHeading(canvasElement, i18n.t('settings.verification_code_title'));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('onboarding.btn_back')));
  await within(canvasElement).findByText(i18n.t('settings.status_active'));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('settings.show_code')));
  await playFindHeading(canvasElement, i18n.t('settings.verification_code_title'));
  await playFindButton(canvasElement, i18n.t('onboarding.btn_back'));
};

HomeToVerificationCodeStory.parameters = { ...HomeToVerificationCodeStory.parameters, design: consoleFrame('4877-7889') };
export const HomeToVerificationCode = prepareStory(HomeToVerificationCodeStory);

const HomeDisabledForAccountStory = Template.bind({});
HomeDisabledForAccountStory.args = { ...baseArgs };
HomeDisabledForAccountStory.parameters = { msw: { handlers: directoryDisabled } };
HomeDisabledForAccountStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('settings.status_off_for_account'));
  // Nothing but the review while the account is off.
  expect(within(canvasElement).queryByRole('button', { name: i18n.t('settings.add_device') })).toBeNull();
  await playFindButton(canvasElement, i18n.t('settings.review_options'));
};

HomeDisabledForAccountStory.parameters = { ...HomeDisabledForAccountStory.parameters, design: consoleFrame('4878-8784') };
export const HomeDisabledForAccount = prepareStory(HomeDisabledForAccountStory);

const HomeNotSetUpStory = Template.bind({});
HomeNotSetUpStory.args = { ...baseArgs };
HomeNotSetUpStory.parameters = {
  encryption: { hasKeys: async () => ({ hasKeys: false }) },
  msw: { handlers: [directoryInSync] },
};
HomeNotSetUpStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('settings.status_not_set_up'));
  await playFindButton(canvasElement, i18n.t('settings.set_up'));
};

HomeNotSetUpStory.parameters = { ...HomeNotSetUpStory.parameters, design: consoleFrame('4878-9504') };
export const HomeNotSetUp = prepareStory(HomeNotSetUpStory);

const VaultNotReadyStory = Template.bind({});
VaultNotReadyStory.args = { ...baseArgs };
VaultNotReadyStory.parameters = {
  encryption: { isReady: false },
  msw: { handlers: [directoryInSync] },
};
VaultNotReadyStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('settings.loading'));
};

export const VaultNotReady = prepareStory(VaultNotReadyStory);

// The vault on the server still fails its integrity check after the vault's own
// retry: a non-blocking warning, with a way to check again.
const SyncIntegrityFailedStory = Template.bind({});
SyncIntegrityFailedStory.args = { ...baseArgs };
SyncIntegrityFailedStory.parameters = {
  ...HomeStory.parameters,
  encryption: { syncVault: async () => ({ status: 'integrity-error', revision: 4 }) },
};
SyncIntegrityFailedStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('settings.sync_integrity_failed'));
  await playFindButton(canvasElement, i18n.t('settings.sync_integrity_retry'));
  // Not blocking: the rest of the settings stays available.
  await playFindButton(canvasElement, i18n.t('settings.add_device'));
};

export const SyncIntegrityFailed = prepareStory(SyncIntegrityFailedStory);

// --- The flows a product's account page opens on their own ------------------

// "Manage encryption": turn it off on this device or for the account. The
// button unlocks only once the user acknowledged what they lose.
const ManageStory = Template.bind({});
ManageStory.args = { ...baseArgs, section: 'manage' };
ManageStory.parameters = { msw: { handlers: [directoryInSync] } };
// Ends ready to turn encryption off for the account: that scope chosen, its warning
// acknowledged.
ManageStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  await playFindHeading(canvasElement, i18n.t('settings.manage_title'));
  // Opened on its own: no way back to a home that was never shown.
  expect(within(canvasElement).queryByRole('button', { name: i18n.t('onboarding.btn_back') })).toBeNull();
  await expect(await playFindButton(canvasElement, i18n.t('settings.turn_off_button'))).toBeDisabled();
  await userEvent.click(await canvas.findByText(i18n.t('onboarding.i_understand')));
  await expect(await playFindButton(canvasElement, i18n.t('settings.turn_off_button'))).toBeEnabled();
  // The acknowledgement covers the warning it was given for, not another scope.
  await userEvent.click(await canvas.findByText(i18n.t('settings.delete_scope_account')));
  await canvas.findByText(i18n.t('settings.disable_server_warning'));
  await expect(await playFindButton(canvasElement, i18n.t('settings.turn_off_button'))).toBeDisabled();
  await userEvent.click(await canvas.findByText(i18n.t('onboarding.i_understand')));
  await expect(await playFindButton(canvasElement, i18n.t('settings.turn_off_button'))).toBeEnabled();
};

ManageStory.parameters = { ...ManageStory.parameters, design: [consoleFrame('4877-7804', 'This device'), consoleFrame('4877-6339', 'My account')] };
export const Manage = prepareStory(ManageStory);

const ManageDisabledForAccountStory = Template.bind({});
ManageDisabledForAccountStory.args = { ...baseArgs, section: 'manage' };
ManageDisabledForAccountStory.parameters = { msw: { handlers: directoryDisabled } };
ManageDisabledForAccountStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('settings.remote_disabled_title'));
  await playFindButton(canvasElement, i18n.t('settings.reconcile_reenable'));
  await playFindButton(canvasElement, i18n.t('settings.reconcile_delete_local'));
};

ManageDisabledForAccountStory.parameters = { ...ManageDisabledForAccountStory.parameters, design: consoleFrame('4878-8985') };
export const ManageDisabledForAccount = prepareStory(ManageDisabledForAccountStory);

// Once the account is off, only this device's keys are left to remove (no frame
// of its own in the design).
const ManageTurnOffDeviceOnlyStory = Template.bind({});
ManageTurnOffDeviceOnlyStory.args = { ...baseArgs, section: 'manage' };
ManageTurnOffDeviceOnlyStory.parameters = { msw: { handlers: directoryDisabled } };
ManageTurnOffDeviceOnlyStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('settings.reconcile_delete_local')));
  await playFindHeading(canvasElement, i18n.t('settings.manage_title'));
  await within(canvasElement).findByText(i18n.t('settings.delete_scope_device'));
  expect(within(canvasElement).queryByText(i18n.t('settings.delete_scope_account'))).toBeNull();
};

export const ManageTurnOffDeviceOnly = prepareStory(ManageTurnOffDeviceOnlyStory);

const ManageNeverRegisteredStory = Template.bind({});
ManageNeverRegisteredStory.args = { ...baseArgs, section: 'manage' };
ManageNeverRegisteredStory.parameters = { msw: { handlers: directoryNeverRegistered } };
ManageNeverRegisteredStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('settings.remote_never_title'));
};

export const ManageNeverRegistered = prepareStory(ManageNeverRegisteredStory);

const ManageDivergedStory = Template.bind({});
ManageDivergedStory.args = { ...baseArgs, section: 'manage' };
ManageDivergedStory.parameters = { msw: { handlers: [directoryDiverged] } };
ManageDivergedStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('settings.remote_diverged_title'));
  await within(canvasElement).findByText(i18n.t('settings.key_mismatch'));
  await playFindButton(canvasElement, i18n.t('settings.reconcile_adopt_server'));
};

export const ManageDiverged = prepareStory(ManageDivergedStory);

// Adopting the server's identity deletes this device's keys: asked in-app first.
const ManageDivergedAdoptPromptStory = Template.bind({});
ManageDivergedAdoptPromptStory.args = { ...ManageDivergedStory.args };
ManageDivergedAdoptPromptStory.parameters = ManageDivergedStory.parameters;
ManageDivergedAdoptPromptStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('settings.reconcile_adopt_server')));
  await playFindHeading(document.body, i18n.t('settings.reconcile_adopt_title'));
  await playFindButton(document.body, i18n.t('settings.reconcile_adopt_button'));
};

export const ManageDivergedAdoptPrompt = prepareStory(ManageDivergedAdoptPromptStory);

const VerificationCodeStory = Template.bind({});
VerificationCodeStory.args = { ...baseArgs, section: 'verification-code' };
VerificationCodeStory.parameters = { msw: { handlers: [directoryInSync] } };
VerificationCodeStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('settings.verification_code_title'));
  await within(canvasElement).findByText('Alice Martin');
  await playFindButton(canvasElement, i18n.t('identity.copy_fingerprint'));
  // Opened on its own: no way back to a home that was never shown.
  expect(within(canvasElement).queryByRole('button', { name: i18n.t('onboarding.btn_back') })).toBeNull();
};

VerificationCodeStory.parameters = { ...VerificationCodeStory.parameters, design: consoleFrame('4877-7889') };
export const VerificationCode = prepareStory(VerificationCodeStory);

const RecoveryPhraseStory = Template.bind({});
RecoveryPhraseStory.args = { ...baseArgs, section: 'recovery-phrase' };
// No trusted contact holds an emergency phrase: nothing holds the change back.
RecoveryPhraseStory.parameters = { msw: { handlers: [directoryInSync, handleGetApiEmergencyAccessTrusted({ body: { contacts: [] } })] } };
RecoveryPhraseStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('settings.change_phrase'));
  await within(canvasElement).findByText(i18n.t('settings.change_phrase_warning'));
  // Opened on its own: no way back to a home that was never shown.
  expect(within(canvasElement).queryByRole('button', { name: i18n.t('onboarding.btn_back') })).toBeNull();
};

export const RecoveryPhrase = prepareStory(RecoveryPhraseStory);

// Continue: the new phrase is generated locally and shown with the Recovery Kit.
const RecoveryPhraseBackupStory = Template.bind({});
RecoveryPhraseBackupStory.args = { ...RecoveryPhraseStory.args };
RecoveryPhraseBackupStory.parameters = RecoveryPhraseStory.parameters;
RecoveryPhraseBackupStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('settings.change_phrase_continue')));
  await playFindHeading(canvasElement, i18n.t('settings.change_phrase_new_title'));
  await expect(await playFindButton(canvasElement, i18n.t('settings.change_phrase_confirm_saved'))).toBeDisabled();
};

export const RecoveryPhraseBackup = prepareStory(RecoveryPhraseBackupStory);

// A trusted contact obtained the emergency phrase and is no longer verified: the
// new phrase could not be committed, since the vault refuses to re-arm their
// escrow. So it is said before any phrase is generated, naming them with their
// address (two people can share a name), with the offer to revoke them.
const unverifiedGrantedContact = {
  id: '11111111-1111-1111-1111-111111111111',
  grantee_user_id: '22222222-2222-2222-2222-222222222222',
  grantee_email: 'bob.dupont@numerique.gouv.fr',
  grantee_name: 'Bob Dupont',
  status: 'recoveryApproved' as const,
  wait_time_days: 15,
  created_at_millis: 1_700_000_000_000,
  recovery_requested_at_millis: 1_700_000_000_000,
  deadline_millis: null,
  vault_active: true,
  escrow: sampleEmergencyEscrowRecord,
};

// The stub vault knows no verified identity, so this contact reads as unverified.
const RecoveryPhraseRearmBlockedStory = Template.bind({});
RecoveryPhraseRearmBlockedStory.args = { ...RecoveryPhraseStory.args };
RecoveryPhraseRearmBlockedStory.parameters = {
  msw: { handlers: [directoryInSync, handleGetApiEmergencyAccessTrusted({ body: { contacts: [unverifiedGrantedContact] } })] },
};
RecoveryPhraseRearmBlockedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  const continueButton = await playFindButton(canvasElement, i18n.t('settings.change_phrase_continue'));
  await userEvent.click(continueButton);
  await canvas.findByText(i18n.t('emergency.rearm_blocked', { names: 'Bob Dupont (bob.dupont@numerique.gouv.fr)' }));
  await playFindButton(canvasElement, i18n.t('emergency.rearm_revoke_retry'));
  // Still on the first screen: no phrase was generated.
  await expect(continueButton).toBeDisabled();
  expect(canvas.queryByRole('heading', { name: i18n.t('settings.change_phrase_new_title') })).toBeNull();
};

export const RecoveryPhraseRearmBlocked = prepareStory(RecoveryPhraseRearmBlockedStory);

// Revoking the blocking contact goes on to the new phrase.
let blockingContactRevoked = false;

const RecoveryPhraseRearmRevokedStory = Template.bind({});
RecoveryPhraseRearmRevokedStory.args = { ...RecoveryPhraseStory.args };
RecoveryPhraseRearmRevokedStory.parameters = {
  msw: {
    handlers: [
      directoryInSync,
      handleGetApiEmergencyAccessTrusted(() => Response.json({ contacts: blockingContactRevoked ? [] : [unverifiedGrantedContact] })),
      handleDeleteApiEmergencyAccessById(() => {
        blockingContactRevoked = true;

        return Response.json({ deleted: true });
      }),
    ],
  },
};
RecoveryPhraseRearmRevokedStory.beforeEach = () => {
  blockingContactRevoked = false;
};
RecoveryPhraseRearmRevokedStory.play = async ({ canvasElement }) => {
  await userEvent.click(await playFindButton(canvasElement, i18n.t('settings.change_phrase_continue')));
  await userEvent.click(await playFindButton(canvasElement, i18n.t('emergency.rearm_revoke_retry')));
  await playFindHeading(canvasElement, i18n.t('settings.change_phrase_new_title'));
  expect(within(canvasElement).queryByText(i18n.t('emergency.rearm_blocked', { names: 'Bob Dupont (bob.dupont@numerique.gouv.fr)' }))).toBeNull();
};

export const RecoveryPhraseRearmRevoked = prepareStory(RecoveryPhraseRearmRevokedStory);

// A flow opened on a device without keys points to the setup.
const SectionWithoutKeysStory = Template.bind({});
SectionWithoutKeysStory.args = { ...baseArgs, section: 'verification-code' };
SectionWithoutKeysStory.parameters = {
  encryption: { hasKeys: async () => ({ hasKeys: false }) },
  msw: { handlers: [directoryInSync] },
};
SectionWithoutKeysStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('settings.no_keys_title'));
  await playFindButton(canvasElement, i18n.t('settings.set_up'));
};

export const SectionWithoutKeys = prepareStory(SectionWithoutKeysStory);
