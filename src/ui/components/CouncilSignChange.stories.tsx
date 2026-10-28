import { Meta, StoryFn } from '@storybook/react';
import { expect, userEvent, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { handlePostApiCouncilsByCouncilIdVersionsByVersionSign } from '@encryption/src/ui/api/generated/msw.gen';
import { CouncilSignChange } from '@encryption/src/ui/components/CouncilSignChange';
import { COUNCIL_LABEL, custodianCouncil } from '@encryption/src/ui/testing/council-stories';
import { sampleCouncilMembers, sampleRosterVersion } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof CouncilSignChange;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Modals/CouncilSignChange',
  component: CouncilSignChange,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: 'medium',
      docs: {
        description: {
          component:
            "A custodian reviews and signs a change of their council's membership. Every newcomer's code must be checked with them first; a first version is accepted by each person it names.",
        },
      },
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <CouncilSignChange {...args} />;

const newcomer = { slot: 5, user_id: 'aaaaaaaa-0000-4000-8000-000000000005', identity_public_key: 'AQ' + 'A'.repeat(42), name: 'Élise Garnier' };
const replacement = custodianCouncil({
  proposal: {
    roster: sampleRosterVersion({
      version: 2,
      previous_roster_hash: 'AAAA',
      members: [...sampleCouncilMembers.slice(0, 3), newcomer],
      signatures: [],
    }),
    quorum_missing: 2,
    pending_members: [{ slot: 5, name: newcomer.name }],
    signed_by_me: false,
    may_sign: true,
  },
});

const baseArgs = {
  getIdToken: async () => 'mock-jwt-token',
  userId: sampleCouncilMembers[0].user_id,
  onBack: () => console.log('onBack'),
  onSigned: () => console.log('onSigned'),
};

// David leaves, Élise joins: her code is checked with her before signing.
const ReplacementStory = Template.bind({});
ReplacementStory.args = { ...baseArgs, council: replacement };
ReplacementStory.parameters = {
  msw: { handlers: [handlePostApiCouncilsByCouncilIdVersionsByVersionSign({ body: { activated: false } })] },
};
ReplacementStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await playFindHeading(canvasElement, i18n.t('council.sign_title', { council: COUNCIL_LABEL }));
  await canvas.findByText(i18n.t('council.sign_removed', { names: 'David Moreau', count: 1 }));
  canvas.getByText(i18n.t('council.change_new'));
  const sign = await playFindButton(canvasElement, i18n.t('council.sign_button'));
  expect(sign).toBeDisabled();
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.mark_checked')));
  await canvas.findByText(i18n.t('council.checked'));
  expect(sign).toBeEnabled();
};
export const Replacement = prepareStory(ReplacementStory);

// The first version: everyone vouches for their own key, nothing to check on others.
const FirstVersionStory = Template.bind({});
FirstVersionStory.args = {
  ...baseArgs,
  council: custodianCouncil({
    role: 'invited',
    chain: [],
    proposal: { roster: sampleRosterVersion({ signatures: [] }), quorum_missing: 0, pending_members: [], signed_by_me: false, may_sign: true },
  }),
};
FirstVersionStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('council.sign_first_title', { council: COUNCIL_LABEL }));
  await within(canvasElement).findByText(i18n.t('council.change_me'));
  expect(await playFindButton(canvasElement, i18n.t('council.sign_first_button'))).toBeEnabled();
};
export const FirstVersion = prepareStory(FirstVersionStory);

const AlreadySignedStory = Template.bind({});
AlreadySignedStory.args = { ...baseArgs, council: { ...replacement, proposal: { ...replacement.proposal!, signed_by_me: true } } };
AlreadySignedStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(i18n.t('council.sign_already'));
  expect(await playFindButton(canvasElement, i18n.t('council.sign_button'))).toBeDisabled();
};
export const AlreadySigned = prepareStory(AlreadySignedStory);
