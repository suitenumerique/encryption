import { Meta, StoryFn } from '@storybook/react';
import { expect, userEvent, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { playFindButton, playFindHeading } from '@encryption/.storybook/testing';
import i18n from '@encryption/src/i18n';
import { genesisPeer } from '@encryption/src/shared/council-quorum';
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
    quorum_missing: 3,
    pending_members: [{ slot: 5, name: newcomer.name }],
    escrows_lost: 0,
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
  await playFindHeading(canvasElement, i18n.t('council.sign_title'));
  // The council named once, over its members.
  expect(canvas.getAllByText(COUNCIL_LABEL)).toHaveLength(1);
  await canvas.findByText(i18n.t('council.change_leaving', { names: 'David Moreau' }));
  // Four custodians with a threshold of 2: a change still needs a majority, 3.
  canvas.getByText(i18n.t('council.sign_quorum', { quorum: 3, count: 4 }));
  canvas.getByText(i18n.t('council.change_new'));
  // The change itself, said before anything else: the button confirms it.
  canvas.getByText(i18n.t('council.change_joining', { names: 'Élise Garnier' }));
  // The custodian first, then the newcomer to check, then the others by name.
  const names = [...canvasElement.querySelectorAll('[data-line="name"]')].map((n) => n.textContent);
  expect(names[1]).toBe('Élise Garnier');
  const sign = await playFindButton(canvasElement, i18n.t('council.sign_button'));
  expect(sign).toBeDisabled();
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.mark_checked')));
  await canvas.findByText(i18n.t('council.checked'));
  expect(sign).toBeEnabled();
};
export const Replacement = prepareStory(ReplacementStory);

// The first version: each member vouches for their own key and checks the next one by slot.
const FirstVersionStory = Template.bind({});
FirstVersionStory.args = {
  ...baseArgs,
  council: custodianCouncil({
    role: 'invited',
    chain: [],
    proposal: {
      roster: sampleRosterVersion({ signatures: [] }),
      quorum_missing: 0,
      pending_members: [],
      escrows_lost: 0,
      signed_by_me: false,
      may_sign: true,
    },
  }),
};
FirstVersionStory.play = async ({ canvasElement }) => {
  await playFindHeading(canvasElement, i18n.t('council.sign_first_title'));
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.change_me'));
  const members = sampleRosterVersion().members.map((m) => ({ slot: m.slot, userId: m.user_id, name: m.name ?? `#${m.slot}` }));
  const peer = genesisPeer(members, baseArgs.userId!)!;
  canvas.getByText(i18n.t('council.sign_check_peer', { name: peer.name }), { exact: false });
  canvas.getByText(i18n.t('council.sign_check_why'));
  // Only that one colleague is to check: a single button.
  const sign = await playFindButton(canvasElement, i18n.t('council.sign_first_button'));
  expect(sign).toBeDisabled();
  expect(canvas.getAllByRole('button', { name: i18n.t('council.mark_checked') })).toHaveLength(1);
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.mark_checked')));
  await canvas.findByText(i18n.t('council.checked'));
  expect(sign).toBeEnabled();
};
export const FirstVersion = prepareStory(FirstVersionStory);

const AlreadySignedStory = Template.bind({});
AlreadySignedStory.args = { ...baseArgs, council: { ...replacement, proposal: { ...replacement.proposal!, signed_by_me: true } } };
AlreadySignedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.sign_already'));
  expect(await playFindButton(canvasElement, i18n.t('council.sign_button'))).toBeDisabled();
  // Nothing left to check once signed.
  expect(canvas.queryByRole('button', { name: i18n.t('council.mark_checked') })).toBeNull();
};
export const AlreadySigned = prepareStory(AlreadySignedStory);

// Élise's side of the same change: she joins a council in force, so she accepts
// the role and vouches for her own key; checking newcomers is the others' part.
const NewcomerStory = Template.bind({});
NewcomerStory.args = { ...baseArgs, userId: 'aaaaaaaa-0000-4000-8000-000000000005', council: replacement };
NewcomerStory.parameters = ReplacementStory.parameters;
NewcomerStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await playFindHeading(canvasElement, i18n.t('council.sign_first_title'));
  await canvas.findByText(i18n.t('council.change_me'));
  expect(canvas.queryByText(i18n.t('council.sign_quorum', { quorum: 3, count: 4 }))).toBeNull();
  expect(canvas.queryByRole('button', { name: i18n.t('council.mark_checked') })).toBeNull();
  expect(await playFindButton(canvasElement, i18n.t('council.sign_first_button'))).toBeEnabled();
};
export const NewcomerAccepts = prepareStory(NewcomerStory);

// Alice started over: the change names her again under her new identity. Hers to
// accept, not a change about someone else to confirm.
const aliceBack = custodianCouncil({
  proposal: {
    roster: sampleRosterVersion({
      version: 2,
      previous_roster_hash: 'AAAA',
      members: sampleCouncilMembers.map((m) => (m.slot === 1 ? { ...m, identity_public_key: 'AQ' + 'B'.repeat(42) } : m)),
      signatures: [],
    }),
    quorum_missing: 3,
    pending_members: [{ slot: 1, name: 'Alice Martin' }],
    escrows_lost: 0,
    signed_by_me: false,
    may_sign: true,
  },
});
const ReturnStory = Template.bind({});
ReturnStory.args = { ...baseArgs, council: aliceBack };
ReturnStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await playFindHeading(canvasElement, i18n.t('council.sign_return_title'));
  canvas.getByText(i18n.t('council.sign_return_description'));
  // On her own line: herself, back after starting over.
  canvas.getByText(i18n.t('council.change_me'));
  canvas.getByText(i18n.t('council.change_new_key'));
  expect(canvas.queryByText(i18n.t('council.change_new_keys', { names: 'Alice Martin' }))).toBeNull();
  expect(await playFindButton(canvasElement, i18n.t('council.sign_first_button'))).toBeEnabled();
};
export const MemberReturns = prepareStory(ReturnStory);

// The same change from Bruno's side: what changes is said first, and Alice's new access is checked with her.
const ReturnSeenStory = Template.bind({});
ReturnSeenStory.args = { ...baseArgs, userId: sampleCouncilMembers[1].user_id, council: aliceBack };
ReturnSeenStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await playFindHeading(canvasElement, i18n.t('council.sign_title'));
  canvas.getByText(i18n.t('council.sign_change_heading'));
  canvas.getByText(i18n.t('council.change_new_keys', { names: 'Alice Martin' }));
  canvas.getByText(i18n.t('council.change_new_key'));
  expect(await playFindButton(canvasElement, i18n.t('council.sign_button'))).toBeDisabled();
};
export const MemberReturnSeenByOthers = prepareStory(ReturnSeenStory);

// Too many current members leave at once: the setups they held can no longer be
// moved. Said in red, and confirming takes an explicit acknowledgement.
const LosesStory = Template.bind({});
LosesStory.args = { ...baseArgs, council: { ...replacement, proposal: { ...replacement.proposal!, escrows_lost: 12 } } };
LosesStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.sign_loses_title', { count: 12 }));
  canvas.getByText(i18n.t('council.sign_loses_description', { count: 12, threshold: 2 }));
  // Even once the newcomer is checked, the loss must be acknowledged.
  await userEvent.click(await playFindButton(canvasElement, i18n.t('council.mark_checked')));
  await canvas.findByText(i18n.t('council.checked'));
  const sign = await playFindButton(canvasElement, i18n.t('council.sign_button'));
  expect(sign).toBeDisabled();
  await userEvent.click(canvas.getByRole('checkbox', { name: i18n.t('council.sign_loses_accept', { count: 12 }) }));
  expect(sign).toBeEnabled();
};
export const ChangeLosesSetups = prepareStory(LosesStory);

// David's side of the replacement: the change removes him, and his confirmation still counts.
const LeavingStory = Template.bind({});
LeavingStory.args = { ...baseArgs, userId: sampleCouncilMembers[3].user_id, council: replacement };
LeavingStory.parameters = ReplacementStory.parameters;
LeavingStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.sign_leave_title'));
  canvas.getByText(i18n.t('council.sign_leave_description'));
  await playFindButton(canvasElement, i18n.t('council.sign_leave_button'));
  expect(canvas.queryByText(i18n.t('council.change_leaving', { names: 'David Moreau' }))).toBeNull();
  // The departure the button confirms is the first change listed, before the newcomer.
  const lines = [...(await canvas.findByText(i18n.t('council.sign_change_heading'))).parentElement!.children].map((el) => el.textContent);
  expect(lines.slice(1, 3)).toEqual([i18n.t('council.change_you_leave'), i18n.t('council.change_joining', { names: 'Élise Garnier' })]);
};
export const MemberLeaves = prepareStory(LeavingStory);

// Only the threshold moves: said once, among the changes, not again above them.
const ThresholdStory = Template.bind({});
ThresholdStory.args = {
  ...baseArgs,
  council: {
    ...replacement,
    proposal: {
      ...replacement.proposal!,
      roster: { ...replacement.proposal!.roster, threshold: 3, members: sampleCouncilMembers },
      pending_members: [],
    },
  },
};
ThresholdStory.parameters = ReplacementStory.parameters;
ThresholdStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(i18n.t('council.change_threshold', { before: 2, count: 3 }));
  expect(canvas.queryByText(i18n.t('council.sign_description', { count: 3, total: 4 }))).toBeNull();
};
export const ThresholdChange = prepareStory(ThresholdStory);
