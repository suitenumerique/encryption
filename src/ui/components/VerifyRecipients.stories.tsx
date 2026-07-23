import { Meta, StoryFn } from '@storybook/react';
import { expect, userEvent, within } from '@storybook/test';
import React from 'react';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { MSG_VAULT_CHECK_FINGERPRINTS, MSG_VAULT_FETCH_PUBLIC_KEYS, MSG_VAULT_GET_KNOWN_FINGERPRINTS } from '@encryption/src/shared/constants';
import { VerifyRecipients } from '@encryption/src/ui/components/VerifyRecipients';
import { sampleFingerprint, samplePublicKey } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof VerifyRecipients;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Modals/VerifyRecipients',
  component: VerifyRecipients,
  ...generateMetaDefault({
    parameters: {
      layout: 'padded',
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

export const MultipleRecipients = prepareStory(MultipleRecipientsStory);

const LoadingStory = Template.bind({});
LoadingStory.args = { ...SingleRecipientStory.args };
LoadingStory.parameters = {
  encryption: { request: () => new Promise<unknown>(() => {}) },
};

export const Loading = prepareStory(LoadingStory);

const RecipientWithoutKeysStory = Template.bind({});
RecipientWithoutKeysStory.args = { ...SingleRecipientStory.args };
RecipientWithoutKeysStory.parameters = {
  encryption: { request: vaultResolving([]) },
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

export const WithoutDisplayNames = prepareStory(WithoutDisplayNamesStory);

const MismatchStory = Template.bind({});
MismatchStory.args = { ...SingleRecipientStory.args };
MismatchStory.parameters = {
  encryption: { request: vaultResolving([BOB], 'mismatch') },
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
