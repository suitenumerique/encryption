/**
 * The committed sample export (`sample-export/`, written once by
 * `npm run maintenance:sample-export`), from A to Z with the code the maintenance
 * tool runs: the folder read from disk, decrypted with the development phrase,
 * packed into the archive, the archive read back as an unzip tool reads it, and
 * the set-aside folder opened in turn with the other organization's phrase.
 * Frozen bytes: an export made once must keep decrypting.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';

import { maintenanceKeyIdToFingerprint, maintenanceKeyPairFromPhrase } from '@encryption/src/crypto/maintenance-escrow';
import { DEV_MAINTENANCE_PHRASE } from '@encryption/src/maintenance/dev-maintenance-key';
import { MANIFEST_FILE, parseManifest } from '@encryption/src/maintenance/export-format';
import { OTHER_KEYS_FOLDER, decryptedExportEntries, recoverItems } from '@encryption/src/maintenance/recover';
import {
  SAMPLE_FILES,
  SAMPLE_IDS,
  SAMPLE_OTHER_ORGANIZATION_PHRASE,
  SAMPLE_PLAINTEXTS,
  readZip,
  sampleOtherOrganizationKey,
} from '@encryption/src/maintenance/testing';
import { ZipWriter } from '@encryption/src/maintenance/zip';

const SAMPLE_EXPORT = resolve(import.meta.dirname, 'sample-export');

function readFolder(root: string): Map<string, Uint8Array> {
  const files = new Map<string, Uint8Array>();
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const path = resolve(dir, name);

      if (statSync(path).isDirectory()) walk(path);
      else files.set(relative(root, path).split('\\').join('/'), new Uint8Array(readFileSync(path)));
    }
  };

  walk(root);

  return files;
}

// What the tool does once the folder is picked and the phrase typed: decrypt, then
// zip; read back here the way the custodians' unzip tool will.
async function runTool(phrase: string, folder: Map<string, Uint8Array>): Promise<Map<string, Uint8Array>> {
  const key = await maintenanceKeyPairFromPhrase(phrase);
  const items = parseManifest(new TextDecoder().decode(folder.get(MANIFEST_FILE)));
  const readFile = async (path: string) => folder.get(path);
  const zip = new ZipWriter();

  for await (const entry of decryptedExportEntries(recoverItems(key, items, readFile), readFile)) zip.add(entry.path, entry.data);

  const archive = new Uint8Array(await new Blob(zip.finish() as BlobPart[]).arrayBuffer());

  return new Map(readZip(archive).map((entry) => [entry.name, entry.data]));
}

const manifestOf = (output: Map<string, Uint8Array>) =>
  new Map(
    new TextDecoder()
      .decode(output.get(MANIFEST_FILE))
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as Record<string, string>)
      .map((line) => [line.id, line])
  );

describe('the committed sample export', () => {
  let output: Map<string, Uint8Array>;
  let otherKeyFolder: string;

  beforeAll(async () => {
    output = await runTool(DEV_MAINTENANCE_PHRASE, readFolder(SAMPLE_EXPORT));
    otherKeyFolder = `${OTHER_KEYS_FOLDER}/${maintenanceKeyIdToFingerprint((await sampleOtherOrganizationKey()).keyId)}`;
  });

  it('is the folder a product team hands over: a manifest and the attachments under their object keys', () => {
    expect([...readFolder(SAMPLE_EXPORT).keys()].sort()).toEqual(
      [MANIFEST_FILE, SAMPLE_FILES.logo, SAMPLE_FILES.chart, SAMPLE_FILES.invoice, SAMPLE_FILES.elsewherePhoto].sort()
    );
  });

  it('decrypts every document, attachment, comment and Drive item the development phrase opens', () => {
    const manifest = manifestOf(output);

    expect(Buffer.from(manifest.get(SAMPLE_IDS.report)?.content ?? '', 'base64')).toEqual(Buffer.from(SAMPLE_PLAINTEXTS[SAMPLE_IDS.report]));
    expect(Buffer.from(manifest.get(SAMPLE_IDS.remark)?.content ?? '', 'base64')).toEqual(Buffer.from(SAMPLE_PLAINTEXTS[SAMPLE_IDS.remark]));
    expect(output.get(SAMPLE_FILES.logo)).toEqual(SAMPLE_PLAINTEXTS[SAMPLE_IDS.logo]);
    expect(output.get(SAMPLE_FILES.chart)).toEqual(SAMPLE_PLAINTEXTS[SAMPLE_IDS.chart]);
    // Two levels below a folder that only carries a key.
    expect(output.get(SAMPLE_FILES.invoice)).toEqual(SAMPLE_PLAINTEXTS[SAMPLE_IDS.invoice]);
    expect(manifest.get(SAMPLE_IDS.budget)).toEqual({ id: SAMPLE_IDS.budget, type: 'folder', title: 'Budget 2027' });
  });

  it('keeps the product fields, drops the key material, and reports the damaged copy alone', () => {
    const manifest = manifestOf(output);

    expect(manifest.get(SAMPLE_IDS.logo)).toEqual({
      id: SAMPLE_IDS.logo,
      type: 'attachment',
      parent: SAMPLE_IDS.report,
      fileName: 'logo.png',
      file: SAMPLE_FILES.logo,
    });
    expect(manifest.get(SAMPLE_IDS.damaged)).toEqual({
      id: SAMPLE_IDS.damaged,
      type: 'document',
      title: 'Copie endommagée',
      updatedAt: '2026-10-19T09:30:00.000Z',
      error: expect.stringMatching(/^WRONG_SECRET_KEY: /),
    });
    expect([...manifest.values()].filter((line) => line.error)).toHaveLength(1);
  });

  it("sets the other organization's items aside, and its custodians open them from that folder alone", async () => {
    expect(manifestOf(output).has(SAMPLE_IDS.elsewhere)).toBe(false);

    const handedOver = new Map(
      [...output].filter(([path]) => path.startsWith(`${otherKeyFolder}/`)).map(([path, data]) => [path.slice(otherKeyFolder.length + 1), data])
    );

    expect([...handedOver.keys()].sort()).toEqual([MANIFEST_FILE, SAMPLE_FILES.elsewherePhoto].sort());

    const theirs = await runTool(SAMPLE_OTHER_ORGANIZATION_PHRASE, handedOver);

    expect(Buffer.from(manifestOf(theirs).get(SAMPLE_IDS.elsewhere)?.content ?? '', 'base64')).toEqual(
      Buffer.from(SAMPLE_PLAINTEXTS[SAMPLE_IDS.elsewhere])
    );
    expect(theirs.get(SAMPLE_FILES.elsewherePhoto)).toEqual(SAMPLE_PLAINTEXTS[SAMPLE_IDS.elsewherePhoto]);
  });
});
