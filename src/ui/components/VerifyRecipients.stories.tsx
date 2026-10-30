import { Meta, StoryFn } from '@storybook/react';
import { expect, userEvent, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindDialog } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { MSG_VAULT_CHECK_FINGERPRINTS, MSG_VAULT_FETCH_PUBLIC_KEYS, MSG_VAULT_GET_KNOWN_FINGERPRINTS } from '@encryption/src/shared/constants';
import { VerifyRecipients } from '@encryption/src/ui/components/VerifyRecipients';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { sampleFingerprint, samplePublicKey } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof VerifyRecipients;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Modals/VerifyRecipients',
  component: VerifyRecipients,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <VerifyRecipients {...args} />;

const BOB = 'bob@numerique.gouv.fr';
const CAROL = 'carol@numerique.gouv.fr';

// Resolution happens in the VAULT (postMessage), not over HTTP, so scenarios
// override `request` instead of using MSW handlers. Only 'mismatch' and 'refused'
// are storied because only those reach the screen: any other status resolves the
// overlay without ever showing it.
function vaultResolving(knownSubs: string[], status: 'refused' | 'mismatch' = 'refused', fingerprints: Record<string, unknown> = {}) {
  return async (type: string, payload?: unknown) => {
    if (type === MSG_VAULT_FETCH_PUBLIC_KEYS) {
      const subs = ((payload as { subs?: string[] } | undefined)?.subs ?? []).filter((sub) => knownSubs.includes(sub));

      return {
        users: Object.fromEntries(
          subs.map((sub, index) => [
            sub,
            { userId: `${samplePublicKey.user_id.slice(0, -1)}${index}`, identityFingerprint: sampleFingerprint, verified: true },
          ])
        ),
      };
    }

    if (type === MSG_VAULT_CHECK_FINGERPRINTS) {
      const userFingerprints = (payload as { userFingerprints?: Record<string, string> } | undefined)?.userFingerprints ?? {};

      return {
        results: Object.entries(userFingerprints).map(([userId, providedFingerprint]) => ({ userId, providedFingerprint, status })),
      };
    }

    if (type === MSG_VAULT_GET_KNOWN_FINGERPRINTS) {
      return { fingerprints };
    }

    return {};
  };
}

// `onComplete` is not optional: the component calls it as soon as it has an
// outcome, so a story that omits it renders an error instead of its own state.
const baseArgs = {
  onComplete: (outcome: 'resolved' | 'cancelled') => console.log('onComplete', outcome),
};

const SingleRecipientStory = Template.bind({});
SingleRecipientStory.args = {
  ...baseArgs,
  recipients: { [BOB]: { name: 'Bob Dupont', email: BOB } },
};
SingleRecipientStory.parameters = {
  encryption: { request: vaultResolving([BOB]) },
};
SingleRecipientStory.play = async () => {
  const dialog = await playFindDialog(document.body, i18n.t('verify.title'));
  const scope = within(dialog);
  await scope.findByText(i18n.t('verify.note_refused'));
  scope.getByText(i18n.t('profile.decision_refused'));
  scope.getByText('Bob Dupont');
  await playFindButton(dialog, i18n.t('verify.btn_trust'));
  await playFindButton(dialog, i18n.t('verify.btn_refuse'));
  expect(scope.queryByRole('button', { name: i18n.t('verify.btn_cancel') })).toBeNull();
};

export const SingleRecipient = prepareStory(SingleRecipientStory);

const MultipleRecipientsStory = Template.bind({});
MultipleRecipientsStory.args = {
  ...baseArgs,
  recipients: {
    [BOB]: { name: 'Bob Dupont', email: BOB },
    [CAROL]: { name: 'Carol Bernard', email: CAROL },
  },
};
MultipleRecipientsStory.parameters = {
  encryption: { request: vaultResolving([BOB, CAROL]) },
};
// One card and one decision per recipient, plus a way to cancel the whole share.
MultipleRecipientsStory.play = async () => {
  const dialog = await playFindDialog(document.body, i18n.t('verify.title'));
  const scope = within(dialog);
  await scope.findByText(i18n.t('verify.explanation_many'));
  scope.getByText('Bob Dupont');
  scope.getByText('Carol Bernard');
  expect(scope.getAllByRole('button', { name: i18n.t('verify.btn_trust') })).toHaveLength(2);
  expect(scope.getAllByRole('button', { name: i18n.t('verify.btn_refuse') })).toHaveLength(2);
  await playFindButton(dialog, i18n.t('verify.btn_cancel'));
};

export const MultipleRecipients = prepareStory(MultipleRecipientsStory);

const LoadingStory = Template.bind({});
LoadingStory.args = { ...SingleRecipientStory.args };
LoadingStory.parameters = {
  encryption: { request: () => new Promise<unknown>(() => {}) },
};
LoadingStory.play = async () => {
  const dialog = await playFindDialog(document.body, i18n.t('verify.title'));
  await within(dialog).findByRole('status');
  expect(within(dialog).queryByRole('heading')).toBeNull();
};

export const Loading = prepareStory(LoadingStory);

const RecipientWithoutKeysStory = Template.bind({});
RecipientWithoutKeysStory.args = { ...SingleRecipientStory.args };
RecipientWithoutKeysStory.parameters = {
  encryption: { request: vaultResolving([]) },
};
// A hard stop: the recipient is listed, and closing is the only way out.
RecipientWithoutKeysStory.play = async () => {
  const dialog = await playFindDialog(document.body, i18n.t('verify.title'));
  const scope = within(dialog);
  await scope.findByText(i18n.t('verify.recipients_without_keys'));
  expect(scope.getByRole('listitem')).toHaveTextContent('Bob Dupont');
  await playFindButton(dialog, i18n.t('verify.btn_close'));
  expect(scope.queryByRole('button', { name: i18n.t('verify.btn_trust') })).toBeNull();
};

export const RecipientWithoutKeys = prepareStory(RecipientWithoutKeysStory);

const WithoutDisplayNamesStory = Template.bind({});
WithoutDisplayNamesStory.args = {
  ...baseArgs,
  recipients: { [BOB]: { email: BOB }, [CAROL]: { email: CAROL } },
};
WithoutDisplayNamesStory.parameters = {
  encryption: { request: vaultResolving([BOB, CAROL]) },
};
// Each email stands in for the name, once, with no second line.
WithoutDisplayNamesStory.play = async () => {
  const dialog = await playFindDialog(document.body, i18n.t('verify.title'));
  const scope = within(dialog);
  expect(await scope.findAllByText(BOB)).toHaveLength(1);
  expect(scope.getAllByText(CAROL)).toHaveLength(1);
  expect(dialog.querySelector(`.${styles.identitySecondary}`)).toBeNull();
};

export const WithoutDisplayNames = prepareStory(WithoutDisplayNamesStory);

const MismatchStory = Template.bind({});
MismatchStory.args = { ...SingleRecipientStory.args };
MismatchStory.parameters = {
  encryption: { request: vaultResolving([BOB], 'mismatch') },
};
// A changed key is the warning case, not the refused one.
MismatchStory.play = async () => {
  const dialog = await playFindDialog(document.body, i18n.t('verify.title'));
  const scope = within(dialog);
  await scope.findByText(i18n.t('verify.note_changed'));
  scope.getByText(i18n.t('profile.decision_changed'));
  expect(dialog.querySelector(`.${styles.card}`)).toHaveClass(styles.cardWarning);
  await playFindButton(dialog, i18n.t('verify.btn_trust'));
};

export const Mismatch = prepareStory(MismatchStory);

// Accepting resolves the mismatch, so the warning that described it must go: the
// share button unlocks, and only the success state is left.
const MismatchAcceptedStory = Template.bind({});
MismatchAcceptedStory.args = { ...MismatchStory.args };
MismatchAcceptedStory.parameters = MismatchStory.parameters;
MismatchAcceptedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  await userEvent.click(await playFindButton(canvasElement, i18n.t('verify.btn_trust')));
  await canvas.findByText(i18n.t('verify.trusted'));
  expect(canvas.queryByText(i18n.t('verify.note_changed'))).toBeNull();
};

export const MismatchAccepted = prepareStory(MismatchAcceptedStory);
