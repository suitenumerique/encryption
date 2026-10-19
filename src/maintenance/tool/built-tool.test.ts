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

import {
  computeMaintenanceKeyFingerprint,
  exportMaintenancePublicKey,
  maintenanceKeyIdToFingerprint,
  maintenanceKeyPairFromPhrase,
  parseMaintenancePublicKey,
} from '@encryption/src/crypto/maintenance-escrow';
import { DEV_MAINTENANCE_PHRASE, DEV_MAINTENANCE_PUBLIC_KEY } from '@encryption/src/maintenance/dev-maintenance-key';
import { MANIFEST_FILE } from '@encryption/src/maintenance/export-format';
import { SAMPLE_FILES, SAMPLE_IDS, SAMPLE_PLAINTEXTS, SAMPLE_TEXTS, readZip, sampleOtherOrganizationKey } from '@encryption/src/maintenance/testing';
import { formatDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

const TOOL = resolve(import.meta.dirname, '../../../dist/maintenance/maintenance-tool.html');
const SAMPLE_EXPORT = resolve(import.meta.dirname, '../sample-export');
const ENGINES = { chromium, firefox, webkit };
const browsers = (process.env.MAINTENANCE_TOOL_BROWSERS ?? 'chromium').split(',') as (keyof typeof ENGINES)[];

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
    });

    await page.goto(pathToFileURL(TOOL).href);
  }, 60_000);

  afterAll(async () => {
    await browser?.close();
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
    await page.setInputFiles('input[type="file"]', SAMPLE_EXPORT);
    await expect.poll(() => page.getByRole('status').first().textContent()).toBe('sample-export: 10 items, 4 files');

    await page.getByLabel('Maintenance phrase').fill(DEV_MAINTENANCE_PHRASE);

    const fingerprint = formatDecimalFingerprint(await computeMaintenanceKeyFingerprint(DEV_MAINTENANCE_PUBLIC_KEY));
    await expect.poll(() => page.locator('.mt-fingerprint').first().textContent()).toBe(fingerprint);

    await page.getByRole('button', { name: 'Decrypt the export' }).click();
    await expect.poll(() => page.getByText('7 items decrypted, 1 failed.').count()).toBe(1);
    await expect.poll(() => page.getByText(/^2 items are escrowed for other maintenance keys/).count()).toBe(1);

    await page
      .getByRole('row', { name: new RegExp(SAMPLE_IDS.report) })
      .getByRole('button', { name: 'Preview' })
      .click();
    await expect.poll(() => page.locator('.mt-preview-text').textContent()).toBe(SAMPLE_TEXTS.report);

    // The image preview goes through a data: URL, the one source the policy grants images.
    await page
      .getByRole('row', { name: new RegExp(SAMPLE_IDS.logo) })
      .getByRole('button', { name: 'Preview' })
      .click();
    await expect.poll(() => page.locator('.mt-preview-image').evaluate((image: HTMLImageElement) => image.complete && image.naturalWidth)).toBe(1);

    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('link', { name: 'Download the decrypted export (.zip)' }).click(),
    ]);

    expect(download.suggestedFilename()).toBe('sample-export-decrypted.zip');

    const entries = Object.fromEntries(readZip(new Uint8Array(readFileSync(await download.path()))).map((entry) => [entry.name, entry.data]));
    const manifest = new TextDecoder()
      .decode(entries[MANIFEST_FILE])
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as Record<string, string>);
    const otherKeyFolder = `other-keys/${maintenanceKeyIdToFingerprint((await sampleOtherOrganizationKey()).keyId)}`;

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
  });

  it('generates a phrase whose public key is the one it shows and the server accepts', async () => {
    await page.getByRole('tab', { name: 'Generate a maintenance key' }).click();
    await page.getByRole('combobox').selectOption('english');
    await page.getByRole('button', { name: 'Generate a maintenance key' }).click();

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

  it('made no request and logged no error, policy violations included', () => {
    expect(requests).toEqual([]);
    expect(errors).toEqual([]);
  });
});
