/**
 * The maintenance tool as operators get it: the BUILT single file, opened from disk
 * in a real browser, the committed sample export (`src/maintenance/sample-export/`)
 * picked from disk, the phrase typed. Proves
 * what the unit tests and the story cannot: the file needs nothing beside it, its
 * Content-Security-Policy lets the WebAssembly and the image preview run, and it
 * makes no request at all.
 *
 * Run by `npm run test:maintenance-tool`, which builds the file first. Chromium by
 * default; `MAINTENANCE_TOOL_BROWSERS=chromium,firefox,webkit` tries the others.
 */
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { type Browser, type Page, chromium, firefox, webkit } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { base64ToUint8, unwrapMaintenanceKey } from '@encryption/src/crypto';
import {
  computeMaintenanceKeyFingerprint,
  exportMaintenancePublicKey,
  maintenanceKeyIdToFingerprint,
  maintenanceKeyPairFromPhrase,
  parseMaintenancePublicKey,
} from '@encryption/src/crypto/maintenance-escrow';
import {
  DEV_MAINTENANCE_PHRASE,
  DEV_MAINTENANCE_PUBLIC_KEY,
  DEV_NEXT_MAINTENANCE_PHRASE,
  DEV_NEXT_MAINTENANCE_PUBLIC_KEY,
} from '@encryption/src/maintenance/dev-maintenance-key';
import { MANIFEST_FILE } from '@encryption/src/maintenance/export-format';
import {
  SAMPLE_FILES,
  SAMPLE_IDS,
  SAMPLE_IMAGE_SIZE,
  SAMPLE_PLAINTEXTS,
  SAMPLE_TEXTS,
  readZip,
  sampleOtherOrganizationKey,
} from '@encryption/src/maintenance/testing';
import { formatDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

const TOOL = resolve(import.meta.dirname, '../../../dist/maintenance/maintenance-tool.html');
const SAMPLE_EXPORT = resolve(import.meta.dirname, '../sample-export');
const ENGINES = { chromium, firefox, webkit };
const browsers = (process.env.MAINTENANCE_TOOL_BROWSERS ?? 'chromium').split(',') as (keyof typeof ENGINES)[];

// The decrypted sample export, whichever way it was written.
function expectDecryptedExport(entries: Record<string, Uint8Array>) {
  const otherKeyFolder = `other-keys/${OTHER_KEY_FINGERPRINT}`;
  const manifest = new TextDecoder()
    .decode(entries[MANIFEST_FILE])
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as Record<string, string>);

  expect(Object.keys(entries).sort()).toEqual(
    [
      SAMPLE_FILES.logo,
      SAMPLE_FILES.chart,
      SAMPLE_FILES.invoice,
      `${otherKeyFolder}/${SAMPLE_FILES.elsewherePhoto}`,
      `${otherKeyFolder}/${MANIFEST_FILE}`,
      MANIFEST_FILE,
    ].sort()
  );

  for (const [file, id] of [
    [SAMPLE_FILES.logo, SAMPLE_IDS.logo],
    [SAMPLE_FILES.chart, SAMPLE_IDS.chart],
    [SAMPLE_FILES.invoice, SAMPLE_IDS.invoice],
  ]) {
    expect(entries[file], file).toEqual(SAMPLE_PLAINTEXTS[id]);
  }

  expect(manifest.map((line) => [line.id, line.error === undefined])).toEqual([
    [SAMPLE_IDS.report, true],
    [SAMPLE_IDS.logo, true],
    [SAMPLE_IDS.chart, true],
    [SAMPLE_IDS.remark, true],
    [SAMPLE_IDS.budget, true],
    [SAMPLE_IDS.annexes, true],
    [SAMPLE_IDS.invoice, true],
    [SAMPLE_IDS.damaged, false],
  ]);
  expect(Buffer.from(manifest[0].content, 'base64').toString()).toBe(SAMPLE_TEXTS.report);
}

let OTHER_KEY_FINGERPRINT: string;

beforeAll(async () => {
  OTHER_KEY_FINGERPRINT = maintenanceKeyIdToFingerprint((await sampleOtherOrganizationKey()).keyId);
});

describe.each(browsers)('the built maintenance tool in %s', (name) => {
  let browser: Browser;
  let page: Page;
  const requests: string[] = [];
  const errors: string[] = [];

  beforeAll(async () => {
    if (!existsSync(TOOL)) throw new Error(`${TOOL} is missing: run "npm run build:maintenance" first`);

    browser = await ENGINES[name].launch();
    page = await (await browser.newContext({ locale: 'en-US', acceptDownloads: true })).newPage();

    page.on('request', (request) => {
      if (!/^(file|blob|data):/.test(request.url())) requests.push(request.url());
    });
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (message) => {
      if (message.type() === 'error') errors.push(message.text());
    });
    await page.addInitScript(() => {
      document.addEventListener('securitypolicyviolation', (event) => {
        console.error(`CSP violation: ${event.violatedDirective} ${event.blockedURI}`);
      });

      // Playwright cannot answer a folder picker: where the browser has one, it is
      // stood in for by a folder in memory, behind the same handles the real one gives.
      if (typeof (window as { showDirectoryPicker?: unknown }).showDirectoryPicker !== 'function') return;

      const written = new Map<string, Uint8Array>();
      const directory = (prefix: string): object => ({
        name: 'picked',
        getDirectoryHandle: async (name: string, { create }: { create: boolean }) => {
          if (!create && ![...written.keys()].some((path) => path.startsWith(`${prefix}${name}/`))) throw new DOMException('absent', 'NotFoundError');

          return directory(`${prefix}${name}/`);
        },
        getFileHandle: async (name: string) => ({
          createWritable: async () => {
            const parts: number[] = [];

            return {
              write: async (data: Uint8Array) => void parts.push(...data),
              close: async () => void written.set(`${prefix}${name}`, Uint8Array.from(parts)),
            };
          },
        }),
      });

      Object.assign(window, { showDirectoryPicker: async () => directory(''), writtenFolder: written });
    });

    await page.goto(pathToFileURL(TOOL).href);
  }, 60_000);

  afterAll(async () => {
    await browser?.close();
  });

  const storedFiles = () =>
    page.evaluate(async () => {
      const names: string[] = [];

      for await (const entry of (await navigator.storage.getDirectory()) as unknown as AsyncIterable<[string, unknown]>) names.push(entry[0]);

      return names;
    });

  it('is one page with its script and style inline, and a policy that allows no request', async () => {
    const html = readFileSync(TOOL, 'utf8');
    const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)?.[1] ?? '';

    expect(csp).toMatch(/^default-src 'none'; /);
    expect(html).toContain('<meta name="robots" content="noindex, nofollow" />');
    expect(csp).not.toMatch(/connect-src|'unsafe-inline'|'unsafe-eval'/);
    expect(
      await page.evaluate(() => ({
        scripts: [...document.scripts].map((script) => script.src),
        stylesheets: document.querySelectorAll('link[rel="stylesheet"]').length,
      }))
    ).toEqual({ scripts: [''], stylesheets: 0 });
    await expect.poll(() => page.getByRole('heading', { level: 1 }).textContent()).toBe('LaSuite Encryption: maintenance tool');
  });

  it('decrypts an export folder picked from disk, previews it and hands back the archive', async () => {
    await page.setInputFiles('#mt-tabpanel-decrypt input[type="file"]', SAMPLE_EXPORT);
    await expect.poll(() => page.getByRole('status').first().textContent()).toBe('sample-export: 10 items, 4 files');

    // Pasted whole into the first box, as from the downloaded phrase: it spreads over the 24.
    await page.locator('#mt-decrypt-word-0').fill(DEV_MAINTENANCE_PHRASE);

    const fingerprint = formatDecimalFingerprint(await computeMaintenanceKeyFingerprint(DEV_MAINTENANCE_PUBLIC_KEY));
    await expect.poll(() => page.locator('.mt-fingerprint').first().textContent()).toBe(fingerprint);

    await page.getByRole('button', { name: 'Decrypt into a .zip archive' }).click();
    await expect.poll(() => page.getByText('7 items decrypted, 1 failed.').count()).toBe(1);
    await expect.poll(() => page.getByText(/^2 items are escrowed for other maintenance keys/).count()).toBe(1);

    await page
      .getByRole('row', { name: new RegExp(SAMPLE_IDS.report) })
      .getByRole('button', { name: 'Preview' })
      .click();
    await expect.poll(() => page.locator('.mt-preview-text').textContent()).toBe(SAMPLE_TEXTS.report);
    // A wide window (1280px): a panel beside the table, which stays usable, so the
    // next row's preview replaces it without closing it first.
    expect(await page.locator('dialog.mt-preview-side').count()).toBe(1);

    // The image preview goes through a data: URL, the one source the policy grants images.
    await page
      .getByRole('row', { name: new RegExp(SAMPLE_IDS.logo) })
      .getByRole('button', { name: 'Preview' })
      .click();
    await expect
      .poll(() => page.locator('.mt-preview-image').evaluate((image: HTMLImageElement) => image.complete && image.naturalWidth))
      .toBe(SAMPLE_IMAGE_SIZE.width);
    await page.keyboard.press('Escape');
    await expect.poll(() => page.locator('dialog.mt-preview').count()).toBe(0);

    // A narrow one: a modal dialog over the table, closed by Escape.
    await page.setViewportSize({ width: 800, height: 720 });
    await page
      .getByRole('row', { name: new RegExp(SAMPLE_IDS.report) })
      .getByRole('button', { name: 'Preview' })
      .click();
    await expect.poll(() => page.locator('dialog.mt-preview:modal').count()).toBe(1);
    await page.keyboard.press('Escape');
    await expect.poll(() => page.locator('dialog.mt-preview').count()).toBe(0);
    await page.setViewportSize({ width: 1280, height: 720 });

    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('link', { name: 'Download the decrypted copy (.zip)' }).click(),
    ]);

    expect(download.suggestedFilename()).toBe('sample-export-decrypted.zip');
    expectDecryptedExport(Object.fromEntries(readZip(new Uint8Array(readFileSync(await download.path()))).map((entry) => [entry.name, entry.data])));

    // Firefox builds the archive in its private storage (Chrome refuses that storage
    // to a file:// page, and builds it in memory): deleting it leaves nothing there.
    if (name === 'firefox') {
      const leavingIsHeld = () =>
        page.evaluate(() => {
          const event = new Event('beforeunload', { cancelable: true });

          window.dispatchEvent(event);

          return event.defaultPrevented;
        });

      expect(await storedFiles()).toHaveLength(1); // the archive: the manifests spooled beside it are gone
      expect(await leavingIsHeld()).toBe(true);
      await page.getByRole('button', { name: 'Delete the archive from this browser' }).click();
      await expect.poll(storedFiles).toEqual([]);
      expect(await leavingIsHeld()).toBe(false);
    }
  });

  it.runIf(name === 'chromium')('writes the decrypted copy file by file into a new folder where the browser can', async () => {
    await page.getByRole('button', { name: 'Decrypt into a folder…' }).click();
    await expect.poll(() => page.getByText('Decrypted copy written to picked/sample-export-decrypted.').count()).toBe(1);

    const written = await page.evaluate(() =>
      Object.fromEntries(
        [...(window as unknown as { writtenFolder: Map<string, Uint8Array> }).writtenFolder].map(([path, data]) => [path, [...data]])
      )
    );

    expectDecryptedExport(
      Object.fromEntries(Object.entries(written).map(([path, data]) => [path.replace(/^sample-export-decrypted\//, ''), Uint8Array.from(data)]))
    );

    // A second run into the same place is refused rather than mixed into the first.
    await page.getByRole('button', { name: 'Decrypt into a folder…' }).click();
    await expect.poll(() => page.getByText('picked/sample-export-decrypted already exists', { exact: false }).count()).toBe(1);
  });

  it('generates a phrase whose public key is the one it shows and the server accepts', async () => {
    await page.getByRole('tab', { name: 'Generate a maintenance key' }).click();
    await page.getByRole('combobox').selectOption('english');
    await page.getByRole('button', { name: 'Generate a maintenance key' }).click();
    await page.getByRole('button', { name: 'Generate a new key' }).click();

    const words = await page.locator('.mt-words li').allTextContents();
    const shown = await page.getByRole('textbox', { name: 'The public key (for MAINTENANCE_ESCROW_KEYS)' }).inputValue();

    expect(words).toHaveLength(24);
    expect(parseMaintenancePublicKey(shown)).toHaveLength(1216);
    expect(exportMaintenancePublicKey((await maintenanceKeyPairFromPhrase(words.join(' '))).publicKey)).toBe(shown);

    // The downloaded phrase is the words shown, numbered, beside the fingerprint.
    const [phraseDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('link', { name: 'Download the phrase (.txt)' }).click(),
    ]);
    const phraseText = readFileSync(await phraseDownload.path(), 'utf8');

    expect(phraseDownload.suggestedFilename()).toBe('maintenance-phrase.txt');
    expect(phraseText).toContain(`Key fingerprint: ${formatDecimalFingerprint(await computeMaintenanceKeyFingerprint(shown))}`);
    expect(phraseText).toContain(words.map((word, index) => `${index + 1}. ${word}`).join('\n'));

    // Printing shows the phrase sheet alone, its date and fingerprint included.
    await page.emulateMedia({ media: 'print' });
    expect(await page.locator('.mt-printable').isVisible()).toBe(true);
    expect(await page.locator('h1').evaluate((heading) => getComputedStyle(heading).visibility)).toBe('hidden');
    expect(await page.locator('.mt-printable .mt-print-only').first().isVisible()).toBe(true);
    await page.emulateMedia({ media: 'screen' });
  });

  it('wraps the copies of an export again for a new key, handing back no secret', async () => {
    const oldKey = await maintenanceKeyPairFromPhrase(DEV_MAINTENANCE_PHRASE);
    const newKey = await maintenanceKeyPairFromPhrase(DEV_NEXT_MAINTENANCE_PHRASE);

    await page.getByRole('tab', { name: 'Rotate the maintenance key' }).click();
    await page.setInputFiles('#mt-tabpanel-rotate input[type="file"]', SAMPLE_EXPORT);
    await expect.poll(() => page.getByText('sample-export: 4 copies').count()).toBe(1);
    await page.locator('#mt-rotate-word-0').fill(DEV_MAINTENANCE_PHRASE);
    await page.getByRole('textbox', { name: '3. The new public key' }).fill(DEV_NEXT_MAINTENANCE_PUBLIC_KEY);
    await page.getByRole('button', { name: 'Rotate and download manifest.ndjson' }).click();
    await expect.poll(() => page.getByText('2 copies rotated, 1 failed.').count()).toBe(1);

    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('link', { name: 'Download the rotated copies (manifest.ndjson)' }).click(),
    ]);
    const exported = new Map(
      readFileSync(resolve(SAMPLE_EXPORT, MANIFEST_FILE), 'utf8')
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line) as Record<string, string>)
        .map((line) => [line.id, line])
    );
    const lines = readFileSync(await download.path(), 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as Record<string, string>);

    expect(download.suggestedFilename()).toBe('manifest.ndjson');
    expect(lines.map((line) => [line.id, line.error === undefined])).toEqual([
      [SAMPLE_IDS.report, true],
      [SAMPLE_IDS.budget, true],
      [SAMPLE_IDS.elsewhere, false],
      [SAMPLE_IDS.damaged, false],
    ]);

    for (const line of lines.filter((rotated) => rotated.error === undefined)) {
      // The copy it replaces, exactly as exported, for the product's compare-and-swap;
      // the new one opens with the new phrase to the same key.
      expect(line.previousMaintenanceKey).toBe(exported.get(line.id)?.maintenanceKey);
      expect(await unwrapMaintenanceKey(newKey, base64ToUint8(line.maintenanceKey))).toEqual(
        await unwrapMaintenanceKey(oldKey, base64ToUint8(line.previousMaintenanceKey))
      );
    }
  });

  it('made no request and logged no error, policy violations included', () => {
    expect(requests).toEqual([]);
    expect(errors).toEqual([]);
  });
});
