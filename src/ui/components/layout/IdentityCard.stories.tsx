import { Meta, StoryFn } from '@storybook/react';
import { expect, userEvent, waitFor, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import i18n from '@encryption/src/i18n';
import { Chip, CopyFingerprintButton, IdentityCard } from '@encryption/src/ui/components/layout/IdentityCard';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { sampleFingerprint } from '@encryption/src/ui/testing/fixtures';

type ComponentType = typeof IdentityCard;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Components/IdentityCard',
  component: IdentityCard,
  ...generateMetaDefault({
    parameters: {
      layout: 'centered',
      hostModal: 'card',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <IdentityCard {...args} />;

const fingerprintLabel = (sampleFingerprint.match(/\d{5}/g) ?? []).join(' ');

// The card, its tone on both the border and the digit boxes, and the 8 groups of the fingerprint.
function expectCard(canvasElement: HTMLElement, tone: { card: string; fingerprint: string } | null) {
  const card = canvasElement.querySelector(`.${styles.card}`);
  const fingerprint = within(canvasElement).getByLabelText(fingerprintLabel);
  expect(fingerprint.children).toHaveLength(8);

  for (const toneClass of [styles.cardWarning, styles.cardError, styles.cardSuccess]) {
    if (toneClass === tone?.card) expect(card).toHaveClass(toneClass);
    else expect(card).not.toHaveClass(toneClass);
  }
  for (const toneClass of [styles.fingerprintWarning, styles.fingerprintError, styles.fingerprintSuccess]) {
    if (toneClass === tone?.fingerprint) expect(fingerprint).toHaveClass(toneClass);
    else expect(fingerprint).not.toHaveClass(toneClass);
  }
}

const baseArgs = {
  name: 'Amandine Salambo',
  secondary: 'amandine.salambo@numerique.gouv.fr',
  fingerprint: sampleFingerprint,
};

const DefaultStory = Template.bind({});
DefaultStory.args = { ...baseArgs };
DefaultStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(baseArgs.name);
  const email = canvas.getByText(baseArgs.secondary);
  expectCard(canvasElement, null);
  // Both lines fit: resting on them adds nothing.
  await userEvent.hover(canvasElement);
  await userEvent.hover(email);
  await new Promise((resolve) => setTimeout(resolve, 700));
  expect(document.body.querySelector('.c__tooltip')).toBeNull();
  await userEvent.unhover(email);
  expect(canvas.queryByRole('button')).toBeNull();
};

export const Default = prepareStory(DefaultStory);

// One's own identity, as settings shows it: the copy control is for sending
// the fingerprint to a contact, so it never appears on a contact's card.
const OwnIdentityStory = Template.bind({});
OwnIdentityStory.args = { ...baseArgs, aside: <CopyFingerprintButton fingerprint={sampleFingerprint} /> };
OwnIdentityStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText(baseArgs.name);
  expectCard(canvasElement, null);
  expect(await within(canvasElement).findByRole('button', { name: i18n.t('identity.copy_fingerprint') })).toBeEnabled();
};

export const OwnIdentity = prepareStory(OwnIdentityStory);

const EmailOnlyStory = Template.bind({});
EmailOnlyStory.args = { name: 'amandine.salambo@numerique.gouv.fr', fingerprint: sampleFingerprint };
// The email is the only line: shown once, as the name.
EmailOnlyStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  expect(await canvas.findAllByText(baseArgs.secondary)).toHaveLength(1);
  expect(canvasElement.querySelector(`.${styles.identitySecondary}`)).toBeNull();
  expectCard(canvasElement, null);
};

export const EmailOnly = prepareStory(EmailOnlyStory);

// A changed key: the border and the digit boxes take the warning tint.
const KeyMismatchStory = Template.bind({});
KeyMismatchStory.args = {
  ...baseArgs,
  tone: 'warning',
  aside: (
    <Chip tone="warning" icon="warning">
      Key mismatch
    </Chip>
  ),
};
KeyMismatchStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText('Key mismatch');
  expectCard(canvasElement, { card: styles.cardWarning, fingerprint: styles.fingerprintWarning });
};

export const KeyMismatch = prepareStory(KeyMismatchStory);

// Lines the ellipsis cuts show in full on resting the pointer on them, as a
// `title` would. Both are far longer than the card, so they are cut whatever
// font metrics the browser renders with.
const longName = 'Amandine Salambo-de-la-Fontaine-Beauregard';
const longEmail = 'amandine.salambo-de-la-fontaine@direction-interministerielle.numerique.gouv.fr';

async function expectHoverTooltip(target: HTMLElement, text: string) {
  await userEvent.hover(target);
  const tooltip = await waitFor(() => {
    const element = document.body.querySelector<HTMLElement>('.c__tooltip');
    expect(element).toHaveTextContent(text);

    return element!;
  });
  await waitFor(() => expect(tooltip).toBeVisible());
  await userEvent.unhover(target);
  await waitFor(() => expect(document.body.querySelector('.c__tooltip')).toBeNull());
}

const CutLinesStory = Template.bind({});
CutLinesStory.args = { ...KeyMismatchStory.args, name: longName, secondary: longEmail };
CutLinesStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  const name = await canvas.findByText(longName);

  // A tooltip waits for the pointer to have moved, as a real mouse does before entering.
  await userEvent.hover(canvasElement);
  await expectHoverTooltip(name, longName);
  await expectHoverTooltip(canvas.getByText(longEmail), longEmail);
};

export const CutLines = prepareStory(CutLinesStory);

const TrustedStory = Template.bind({});
TrustedStory.args = {
  ...baseArgs,
  tone: 'success',
  aside: (
    <Chip tone="success" icon="trusted">
      Trusted
    </Chip>
  ),
};
TrustedStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText('Trusted');
  expectCard(canvasElement, { card: styles.cardSuccess, fingerprint: styles.fingerprintSuccess });
};

export const Trusted = prepareStory(TrustedStory);

const RefusedStory = Template.bind({});
RefusedStory.args = {
  ...baseArgs,
  tone: 'error',
  aside: (
    <Chip tone="error" icon="refused">
      Refused
    </Chip>
  ),
};
RefusedStory.play = async ({ canvasElement }) => {
  await within(canvasElement).findByText('Refused');
  expectCard(canvasElement, { card: styles.cardError, fingerprint: styles.fingerprintError });
};

export const Refused = prepareStory(RefusedStory);

// No fingerprint (a contact who has not set up encryption yet).
const WithoutFingerprintStory = Template.bind({});
WithoutFingerprintStory.args = { name: 'Amandine Salambo', secondary: 'amandine.salambo@numerique.gouv.fr' };
WithoutFingerprintStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  await canvas.findByText(baseArgs.name);
  canvas.getByText(baseArgs.secondary);
  expect(canvasElement.querySelector(`.${styles.fingerprint}`)).toBeNull();
};

export const WithoutFingerprint = prepareStory(WithoutFingerprintStory);
