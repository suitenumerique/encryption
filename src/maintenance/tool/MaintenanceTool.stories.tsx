import { Meta, StoryFn } from '@storybook/react';
import { expect, spyOn, userEvent, waitFor, within } from 'storybook/test';

import { StoryHelperFactory } from '@encryption/.storybook/helpers';
import {
  generateMaintenancePhrase,
  importMaintenancePublicKey,
  maintenanceKeyIdToFingerprint,
  maintenanceKeyPairFromPhrase,
  parseMaintenancePublicKey,
} from '@encryption/src/crypto/maintenance-escrow';
import i18n from '@encryption/src/i18n';
import {
  DEV_MAINTENANCE_PHRASE,
  DEV_MAINTENANCE_PUBLIC_KEY,
  DEV_NEXT_MAINTENANCE_PHRASE,
  DEV_NEXT_MAINTENANCE_PUBLIC_KEY,
} from '@encryption/src/maintenance/dev-maintenance-key';
import {
  SAMPLE_FILES,
  SAMPLE_IDS,
  SAMPLE_IMAGE_SIZE,
  SAMPLE_TEXTS,
  buildLongExport,
  buildSampleExport,
  sampleOtherOrganizationKey,
} from '@encryption/src/maintenance/testing';
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
async function pickSampleExport(
  canvasElement: HTMLElement,
  {
    leaveOut = [],
    build = buildSampleExport,
    panel = 'decrypt',
  }: { leaveOut?: string[]; build?: typeof buildSampleExport; panel?: 'decrypt' | 'rotate' } = {}
): Promise<void> {
  const files = Object.entries(await build(await importMaintenancePublicKey(DEV_MAINTENANCE_PUBLIC_KEY)))
    .filter(([path]) => !leaveOut.includes(path))
    .map(([path, data]) => {
      const file = new File([data as BlobPart], path.split('/').pop() as string);

      Object.defineProperty(file, 'webkitRelativePath', { value: `export-2026-10/${path}` });

      return file;
    });

  await userEvent.upload(canvasElement.querySelector(`#mt-tabpanel-${panel} input[type="file"]`) as HTMLInputElement, files);
}

// The whole phrase pasted into the first box, as from a downloaded file: it spreads over the 24.
async function typePhrase(canvasElement: HTMLElement, phrase: string, panel = 'mt-decrypt'): Promise<void> {
  await userEvent.click(canvasElement.querySelector(`#${panel}-word-0`) as HTMLInputElement);
  await userEvent.paste(phrase);
}

const DefaultStory = Template.bind({});
DefaultStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  await canvas.findByRole('heading', { level: 1, name: i18n.t('maintenanceTool.title') });
  expect(canvas.getByRole('button', { name: i18n.t('maintenanceTool.decrypt.runZip') })).toBeDisabled();
};

export const Default = prepareStory(DefaultStory);

const DecryptedStory = Template.bind({});
DecryptedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  await pickSampleExport(canvasElement);
  await canvas.findByText(i18n.t('maintenanceTool.decrypt.folderSummary', { folder: 'export-2026-10', items: 10, files: 4 }));

  await typePhrase(canvasElement, DEV_MAINTENANCE_PHRASE);
  await canvas.findByText(i18n.t('maintenanceTool.decrypt.fingerprint'), { exact: false });

  // Read from the copies' headers before anything is decrypted: 3 of the 4 roots are for this key.
  expect(canvas.getByText(i18n.t('maintenanceTool.decrypt.coverageSome', { ours: 3, roots: 4 }))).toBeVisible();

  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.decrypt.runZip') }));
  await canvas.findByText(i18n.t('maintenanceTool.decrypt.summary', { ok: 7, failed: 1 }));
  const [tookBefore, tookAfter] = i18n.t('maintenanceTool.decrypt.took', { duration: '|' }).split('|');

  expect(canvas.getByText((text) => text.startsWith(tookBefore) && text.endsWith(tookAfter) && /\d+:\d\d/.test(text))).toBeVisible();
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
  expect(await canvas.findByRole('link', { name: i18n.t('maintenanceTool.decrypt.download') })).toHaveAttribute(
    'download',
    'export-2026-10-decrypted.zip'
  );

  expect(within(canvas.getByRole('row', { name: new RegExp(SAMPLE_IDS.damaged) })).getByText(/^WRONG_SECRET_KEY: /)).toBeVisible();

  const previewOf = async (id: string) =>
    userEvent.click(
      within(canvas.getByRole('row', { name: new RegExp(id) })).getByRole('button', { name: i18n.t('maintenanceTool.decrypt.preview') })
    );

  await previewOf(SAMPLE_IDS.report);
  await canvas.findByText(SAMPLE_TEXTS.report, { collapseWhitespace: false, trim: false });
  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.decrypt.closePreview') }));

  // Left open on an image, so the story ends on what a preview looks like.
  await previewOf(SAMPLE_IDS.logo);
  await waitFor(() =>
    expect((canvasElement.querySelector('.mt-preview-image') as HTMLImageElement | null)?.naturalWidth).toBe(SAMPLE_IMAGE_SIZE.width)
  );
};

export const Decrypted = prepareStory(DecryptedStory);

const PhraseOfAnotherKeyStory = Template.bind({});
PhraseOfAnotherKeyStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  // A valid phrase, but not the one this export was made for: said before the run, and after it.
  await pickSampleExport(canvasElement);
  await typePhrase(canvasElement, await generateMaintenancePhrase('english', new Uint8Array(32).fill(3)));
  await canvas.findByText(i18n.t('maintenanceTool.decrypt.coverageNone', { roots: 4 }));

  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.decrypt.runZip') }));
  await canvas.findByText(i18n.t('maintenanceTool.decrypt.noneForThisKey', { count: 10 }));
};

export const PhraseOfAnotherKey = prepareStory(PhraseOfAnotherKeyStory);

const TryItStory = Template.bind({});
TryItStory.parameters = {
  docs: {
    description: {
      story:
        'The sample export picked and the development phrase typed, nothing more: click "Decrypt into a .zip archive" (or into a folder), then "Preview" on a row. The Decrypted story plays the same steps by itself.',
    },
  },
};
TryItStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  await pickSampleExport(canvasElement);
  await typePhrase(canvasElement, DEV_MAINTENANCE_PHRASE);
  await canvas.findByText(i18n.t('maintenanceTool.decrypt.fingerprint'), { exact: false });
  expect(canvas.getByRole('button', { name: i18n.t('maintenanceTool.decrypt.runZip') })).toBeEnabled();
};

export const TryIt = prepareStory(TryItStory);

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

  await canvas.findByText(i18n.t('maintenanceTool.phrase.invalid'));
  expect(canvas.queryByText(i18n.t('maintenanceTool.decrypt.fingerprint'), { exact: false })).toBeNull();
};

export const MistypedPhrase = prepareStory(MistypedPhraseStory);

const UnknownWordStory = Template.bind({});
UnknownWordStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  const words = DEV_MAINTENANCE_PHRASE.split(' ');

  // A misspelled word is flagged in its own box, by its number on the sheet.
  words[4] = `${words[4]}x`;
  await typePhrase(canvasElement, words.join(' '));

  await canvas.findByText(i18n.t('maintenanceTool.phrase.unknownWords', { numbers: '5' }));
  expect(canvasElement.querySelector('#mt-decrypt-word-4')).toHaveAttribute('aria-invalid', 'true');
  expect(canvasElement.querySelector('#mt-decrypt-word-3')).not.toHaveAttribute('aria-invalid');
};

export const UnknownWord = prepareStory(UnknownWordStory);

const LongExportStory = Template.bind({});
LongExportStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  await pickSampleExport(canvasElement, { build: (key) => buildLongExport(key, 249) });
  await typePhrase(canvasElement, DEV_MAINTENANCE_PHRASE);
  await canvas.findByText(i18n.t('maintenanceTool.decrypt.fingerprint'), { exact: false });
  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.decrypt.runZip') }));

  // 250 rows, shown a hundred at a time. The first page waits for the whole run
  // (250 decryptions into the archive), longer than the default second on a
  // loaded machine.
  await canvas.findByText(i18n.t('maintenanceTool.decrypt.pageRange', { from: 1, to: 100, total: 250 }), {}, { timeout: 15000 });
  expect(canvas.getAllByRole('row')).toHaveLength(101);
  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.decrypt.nextPage') }));
  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.decrypt.nextPage') }));
  await canvas.findByText(i18n.t('maintenanceTool.decrypt.pageRange', { from: 201, to: 250, total: 250 }));
  expect(canvas.getByRole('button', { name: i18n.t('maintenanceTool.decrypt.nextPage') })).toBeDisabled();

  await userEvent.click(canvas.getByLabelText(i18n.t('maintenanceTool.decrypt.onlyFailures')));
  expect(canvas.getAllByRole('row')).toHaveLength(1);
};

export const LongExport = prepareStory(LongExportStory);

const PublicKeyOfAPhraseStory = Template.bind({});
PublicKeyOfAPhraseStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  await userEvent.click(canvas.getByRole('tab', { name: i18n.t('maintenanceTool.tabs.publicKey') }));
  await typePhrase(canvasElement, DEV_MAINTENANCE_PHRASE, 'mt-public-key');

  const publicKey = (await canvas.findByRole('textbox', { name: i18n.t('maintenanceTool.publicKey.title') })) as HTMLTextAreaElement;

  expect(publicKey.value).toBe(DEV_MAINTENANCE_PUBLIC_KEY);
};

export const PublicKeyOfAPhrase = prepareStory(PublicKeyOfAPhraseStory);

const GeneratedKeyStory = Template.bind({});
// A fixed seed, so the words and the key shown are the same on every run.
GeneratedKeyStory.args = { seed: Uint8Array.from({ length: 32 }, (_, i) => i) };
GeneratedKeyStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);

  await userEvent.click(canvas.getByRole('tab', { name: i18n.t('maintenanceTool.tabs.generate') }));
  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.generate.button') }));
  // Asked first: a new phrase replaces nothing on the server.
  await canvas.findByRole('alertdialog', { name: i18n.t('maintenanceTool.generate.confirmTitle') });
  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.generate.confirm') }));

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

  // Generating again warns that the phrase shown would be replaced, and cancelling keeps it.
  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.generate.button') }));
  await canvas.findByText(i18n.t('maintenanceTool.generate.confirmReplaceShown'));
  await userEvent.click(canvas.getByRole('button', { name: i18n.t('maintenanceTool.generate.cancel') }));
  expect(canvas.queryByRole('alertdialog')).toBeNull();
  expect(canvasElement.querySelectorAll('.mt-words li')).toHaveLength(24);

  // Handed back, so the buttons work for whoever then clicks them in Storybook.
  writeText.mockRestore();
  print.mockRestore();
};

export const GeneratedKey = prepareStory(GeneratedKeyStory);

const RotatedStory = Template.bind({});
RotatedStory.play = async ({ canvasElement }) => {
  const canvas = within(canvasElement);
  const newKey = await maintenanceKeyPairFromPhrase(DEV_NEXT_MAINTENANCE_PHRASE);

  await userEvent.click(canvas.getByRole('tab', { name: i18n.t('maintenanceTool.tabs.rotate') }));
  await pickSampleExport(canvasElement, { panel: 'rotate' });
  await canvas.findByText(i18n.t('maintenanceTool.rotate.folderSummary', { folder: 'export-2026-10', count: 4 }));
  await typePhrase(canvasElement, DEV_MAINTENANCE_PHRASE, 'mt-rotate');
  await canvas.findByText(i18n.t('maintenanceTool.rotate.coverageSome', { ours: 3, roots: 4 }));

  const runDownload = canvas.getByRole('button', { name: i18n.t('maintenanceTool.rotate.runDownload') });
  const newKeyInput = canvas.getByRole('textbox', { name: i18n.t('maintenanceTool.rotate.newKeyTitle') });

  // The current key pasted by mistake: refused, nothing to rotate to.
  await userEvent.click(newKeyInput);
  await userEvent.paste(DEV_MAINTENANCE_PUBLIC_KEY);
  await canvas.findByText(i18n.t('maintenanceTool.rotate.sameKey'));
  expect(runDownload).toBeDisabled();

  await userEvent.clear(newKeyInput);
  await userEvent.paste(DEV_NEXT_MAINTENANCE_PUBLIC_KEY);
  await canvas.findByText(formatDecimalFingerprint(maintenanceKeyIdToFingerprint(newKey.keyId)));
  await waitFor(() => expect(runDownload).toBeEnabled());

  await userEvent.click(runDownload);
  // Two copies rotated, the damaged one reported, another organization's left alone.
  await canvas.findByText(i18n.t('maintenanceTool.rotate.summary', { ok: 2, failed: 1 }));
  expect(canvas.getByText(i18n.t('maintenanceTool.rotate.otherKeys', { count: 1 }))).toBeVisible();
  expect(canvas.getByRole('link', { name: i18n.t('maintenanceTool.rotate.download') })).toHaveAttribute('download', 'manifest.ndjson');
  expect(canvas.getByText(i18n.t('maintenanceTool.rotate.noSecret'))).toBeVisible();
};

export const Rotated = prepareStory(RotatedStory);
