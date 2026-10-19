import { Meta, StoryFn } from '@storybook/react';
import { expect, spyOn, userEvent, waitFor, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import { importMaintenancePublicKey, maintenanceKeyIdToFingerprint, parseMaintenancePublicKey } from '@encryption/src/crypto/maintenance-escrow';
import i18n from '@encryption/src/i18n';
import { DEV_MAINTENANCE_PHRASE, DEV_MAINTENANCE_PUBLIC_KEY } from '@encryption/src/maintenance/dev-maintenance-key';
import { SAMPLE_FILES, SAMPLE_IDS, SAMPLE_TEXTS, buildSampleExport, sampleOtherOrganizationKey } from '@encryption/src/maintenance/testing';
import { MaintenanceTool } from '@encryption/src/maintenance/tool/MaintenanceTool';
import { formatDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

type ComponentType = typeof MaintenanceTool;
const { generateMetaDefault, prepareStory } = StoryHelperFactory<ComponentType>();

export default {
  title: 'Preview/Pages/MaintenanceTool',
  component: MaintenanceTool,
  ...generateMetaDefault({
    parameters: {
      layout: 'fullscreen',
    },
  }),
} as Meta<ComponentType>;

const Template: StoryFn<ComponentType> = (args) => <MaintenanceTool {...args} />;

// What a folder picker hands over: each file named by its path under the picked folder.
async function pickSampleExport(canvasElement: HTMLElement, { leaveOut = [] }: { leaveOut?: string[] } = {}): Promise<void> {
  const files = Object.entries(await buildSampleExport(await importMaintenancePublicKey(DEV_MAINTENANCE_PUBLIC_KEY)))
    .filter(([path]) => !leaveOut.includes(path))
    .map(([path, data]) => {
      const file = new File([data as BlobPart], path.split('/').pop() as string);

      Object.defineProperty(file, 'webkitRelativePath', { value: `export-2026-10/${path}` });

      return file;
    });

  await userEvent.upload(canvasElement.querySelector('input[type="file"]') as HTMLInputElement, files);
}

async function typePhrase(canvasElement: HTMLElement, phrase: string): Promise<void> {
  await userEvent.click(within(canvasElement).getByLabelText(i18n.t('maintenanceTool.decrypt.phraseLabel')));
  await userEvent.paste(phrase);
}

const DefaultStory = Template.bind({});
DefaultStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  await canvas.findByRole('heading', { level: 1, name: i18n.t('maintenanceTool.title') });
  expect(canvas.getByRole('button', { name: i18n.t('maintenanceTool.decrypt.run') })).toBeDisabled();
};

export const Default = prepareStory(DefaultStory);

const DecryptedStory = Template.bind({});
DecryptedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  await pickSampleExport(canvasElement);
  await canvas.findByText(i18n.t('maintenanceTool.decrypt.folderSummary', { folder: 'export-2026-10', items: 10, files: 4 }));

  await typePhrase(canvasElement, DEV_MAINTENANCE_PHRASE);
  await canvas.findByText(i18n.t('maintenanceTool.decrypt.fingerprint'), { exact: false });

  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.decrypt.run') }));
  await canvas.findByText(i18n.t('maintenanceTool.decrypt.summary', { ok: 7, failed: 1 }));
  // Another organization's document and its attachment: set aside, not failed.
  expect(canvas.getByText(i18n.t('maintenanceTool.decrypt.otherKeys', { count: 2 }))).toBeVisible();
  expect(
    canvas.getByText(
      i18n.t('maintenanceTool.decrypt.otherKeyGroup', {
        fingerprint: formatDecimalFingerprint(maintenanceKeyIdToFingerprint((await sampleOtherOrganizationKey()).keyId)),
        count: 2,
      })
    )
  ).toBeVisible();
  expect(canvas.getByRole('link', { name: i18n.t('maintenanceTool.decrypt.download') })).toHaveAttribute('download', 'export-2026-10-decrypted.zip');

  const documentRow = canvas.getByRole('row', { name: new RegExp(SAMPLE_IDS.report) });

  await userEvent.click(within(documentRow).getByRole('button', { name: i18n.t('maintenanceTool.decrypt.preview') }));
  await canvas.findByText(SAMPLE_TEXTS.report, { collapseWhitespace: false, trim: false });
  expect(within(canvas.getByRole('row', { name: new RegExp(SAMPLE_IDS.damaged) })).getByText(/^WRONG_SECRET_KEY: /)).toBeVisible();
};

export const Decrypted = prepareStory(DecryptedStory);

const MissingAttachmentStory = Template.bind({});
MissingAttachmentStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  // An attachment left in the object storage: said when the folder is picked.
  await pickSampleExport(canvasElement, { leaveOut: [SAMPLE_FILES.logo] });

  await canvas.findByText(i18n.t('maintenanceTool.decrypt.folderMissingFiles', { count: 1, examples: SAMPLE_FILES.logo }));
};

export const MissingAttachment = prepareStory(MissingAttachmentStory);

const MistypedPhraseStory = Template.bind({});
MistypedPhraseStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  const words = DEV_MAINTENANCE_PHRASE.split(' ');

  // Two words swapped: every word exists, the BIP-39 checksum catches the order.
  [words[0], words[1]] = [words[1], words[0]];
  await typePhrase(canvasElement, words.join(' '));

  await canvas.findByText(i18n.t('maintenanceTool.decrypt.phraseInvalid'));
  expect(canvas.queryByText(i18n.t('maintenanceTool.decrypt.fingerprint'), { exact: false })).toBeNull();
};

export const MistypedPhrase = prepareStory(MistypedPhraseStory);

const GeneratedKeyStory = Template.bind({});
// A fixed seed, so the words and the key shown are the same on every run.
GeneratedKeyStory.args = { seed: Uint8Array.from({ length: 32 }, (_, i) => i) };
GeneratedKeyStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  await userEvent.click(canvas.getByRole('tab', { name: i18n.t('maintenanceTool.tabs.generate') }));
  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.generate.button') }));

  await waitFor(() => expect(canvasElement.querySelectorAll('.mt-words li')).toHaveLength(24));

  const publicKey = canvas.getByRole('textbox', { name: i18n.t('maintenanceTool.generate.publicKeyTitle') }) as HTMLTextAreaElement;

  expect(parseMaintenancePublicKey(publicKey.value)).toHaveLength(1216);
  expect(canvas.getByRole('link', { name: i18n.t('maintenanceTool.generate.downloadPublicKey') })).toHaveAttribute(
    'download',
    'maintenance-public-key.txt'
  );

  // Every way to keep the phrase: shown (above), copied, downloaded, printed.
  const writeText = spyOn(navigator.clipboard, 'writeText').mockResolvedValue();
  const print = spyOn(window, 'print').mockImplementation(() => undefined);

  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.generate.copyPhrase') }));
  await canvas.findByText(i18n.t('maintenanceTool.generate.copied'));
  expect(writeText).toHaveBeenCalledWith(expect.stringContaining(`1. ${canvasElement.querySelector('.mt-words li')?.textContent}`));
  expect(canvas.getByRole('link', { name: i18n.t('maintenanceTool.generate.downloadPhrase') })).toHaveAttribute('download', 'maintenance-phrase.txt');
  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.generate.printPhrase') }));
  expect(print).toHaveBeenCalledOnce();
};

export const GeneratedKey = prepareStory(GeneratedKeyStory);
