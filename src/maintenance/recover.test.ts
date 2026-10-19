import { beforeAll, describe, expect, it } from 'vitest';

import { type MaintenanceKeyPair, encryptContent, generateSymmetricKey, uint8ToBase64, wrapKeyForMaintenance } from '@encryption/src/crypto';
import { maintenanceKeyIdToFingerprint, maintenanceKeyPairFromPhrase } from '@encryption/src/crypto/maintenance-escrow';
import { DEV_MAINTENANCE_PHRASE } from '@encryption/src/maintenance/dev-maintenance-key';
import { type ExportItem, MANIFEST_FILE, parseManifest } from '@encryption/src/maintenance/export-format';
import { type ItemResult, decryptedExportEntries, decryptedManifestLine, recoverItems } from '@encryption/src/maintenance/recover';
import { sampleOtherOrganizationKey } from '@encryption/src/maintenance/testing';
import { DOMAIN_CONTENT, DOMAIN_WRAPPED_KEY } from '@encryption/src/shared/crypto-domains';

const bytes = (s: string) => new TextEncoder().encode(s);
const b64 = uint8ToBase64;

let maintenance: MaintenanceKeyPair;

beforeAll(async () => {
  maintenance = await maintenanceKeyPairFromPhrase(DEV_MAINTENANCE_PHRASE);
});

async function collect(items: ExportItem[], files: Record<string, Uint8Array> = {}): Promise<ItemResult[]> {
  const results: ItemResult[] = [];

  for await (const result of recoverItems(maintenance, items, async (path) => files[path])) results.push(result);

  return results;
}

const outcome = (results: ItemResult[]) =>
  Object.fromEntries(results.map((r) => [r.item.id, r.ok ? new TextDecoder().decode(r.plaintext) : r.error]));

describe('recoverItems', () => {
  it('walks a Drive-like tree down from its root, whatever the order of the lines', async () => {
    const root = await generateSymmetricKey();
    const folder = await generateSymmetricKey();
    const file = await generateSymmetricKey();
    const items = parseManifest(
      [
        // The deepest item first: a key is resolved when needed, not in line order.
        { id: 'file', parent: 'folder', wrappedKey: b64(await encryptContent(file, folder, DOMAIN_WRAPPED_KEY)), file: 'blobs/file' },
        { id: 'folder', parent: 'root', wrappedKey: b64(await encryptContent(folder, root, DOMAIN_WRAPPED_KEY)) },
        { id: 'root', maintenanceKey: b64(await wrapKeyForMaintenance(root, maintenance)) },
        { id: 'note', parent: 'folder', content: b64(await encryptContent(bytes('shares the folder key'), folder, DOMAIN_CONTENT)) },
      ]
        .map((item) => JSON.stringify(item))
        .join('\n')
    );

    const results = await collect(items, { 'blobs/file': await encryptContent(bytes('deep down'), file, DOMAIN_CONTENT) });

    expect(results.map((r) => [r.item.id, r.ok])).toEqual([
      ['file', true],
      ['folder', true],
      ['root', true],
      ['note', true],
    ]);
    expect(outcome(results)).toMatchObject({ file: 'deep down', note: 'shares the folder key' });
    expect(results.find((r) => r.item.id === 'folder')).toEqual({ item: expect.anything(), ok: true, plaintext: undefined });
  });

  it('reports each broken item on its own and keeps going', async () => {
    const root = await generateSymmetricKey();
    const maintenanceKey = b64(await wrapKeyForMaintenance(root, maintenance));
    const corrupt = await encryptContent(bytes('x'), root, DOMAIN_CONTENT);
    corrupt[corrupt.length - 1] ^= 1;

    const results = await collect([
      { id: 'orphan', parent: 'nowhere' },
      { id: 'a', parent: 'b' },
      { id: 'b', parent: 'a' },
      { id: 'missing-file', maintenanceKey, file: 'not/there' },
      { id: 'corrupt', maintenanceKey, content: b64(corrupt) },
      { id: 'other-domain', maintenanceKey, content: b64(await encryptContent(bytes('x'), root, DOMAIN_WRAPPED_KEY)) },
      { id: 'fine', maintenanceKey, content: b64(await encryptContent(bytes('still fine'), root, DOMAIN_CONTENT)) },
    ]);

    expect(outcome(results)).toEqual({
      orphan: 'parent nowhere is not in the export',
      a: 'parents loop: a -> b -> a',
      b: 'parents loop: a -> b -> a', // the same loop, found once
      'missing-file': 'file not/there is not in the export folder',
      corrupt: expect.stringMatching(/^WRONG_SECRET_KEY: /),
      'other-domain': expect.stringMatching(/^WRONG_SECRET_KEY: /),
      fine: 'still fine',
    });
  });
});

describe("another organization's items", () => {
  it('are set aside with their key, children included, not reported as damaged', async () => {
    const theirs = await sampleOtherOrganizationKey();
    const root = await generateSymmetricKey();
    const results = await collect([
      {
        id: 'theirs',
        maintenanceKey: b64(await wrapKeyForMaintenance(root, theirs)),
        content: b64(await encryptContent(bytes('x'), root, DOMAIN_CONTENT)),
      },
      { id: 'their-comment', parent: 'theirs', content: b64(await encryptContent(bytes('y'), root, DOMAIN_CONTENT)) },
    ]);
    const fingerprint = maintenanceKeyIdToFingerprint(theirs.keyId);

    expect(results).toEqual([
      { item: expect.objectContaining({ id: 'theirs' }), ok: false, otherKey: fingerprint, error: expect.stringContaining(fingerprint.slice(0, 5)) },
      { item: expect.objectContaining({ id: 'their-comment' }), ok: false, otherKey: fingerprint, error: expect.any(String) },
    ]);
  });

  it('come back still encrypted, files included, as one export folder per key', async () => {
    async function* results(): AsyncGenerator<ItemResult> {
      yield { item: { id: 'd', type: 'document', maintenanceKey: 'AAAA' } as ExportItem, ok: true };
      yield { item: { id: 'x', maintenanceKey: 'BBBB', title: 'Theirs' } as ExportItem, ok: false, error: 'elsewhere', otherKey: '1234' };
      yield { item: { id: 'y', parent: 'x', file: 'att/y' } as ExportItem, ok: false, error: 'elsewhere', otherKey: '1234' };
    }

    const entries = [];

    for await (const entry of decryptedExportEntries(results(), async (path) => (path === 'att/y' ? bytes('sealed') : undefined))) {
      entries.push({ path: entry.path, text: new TextDecoder().decode(entry.data) });
    }

    expect(entries).toEqual([
      { path: 'other-keys/1234/att/y', text: 'sealed' },
      {
        path: `other-keys/1234/${MANIFEST_FILE}`,
        text: '{"id":"x","maintenanceKey":"BBBB","title":"Theirs"}\n{"id":"y","parent":"x","file":"att/y"}\n',
      },
      { path: MANIFEST_FILE, text: '{"id":"d","type":"document"}\n' },
    ]);
  });
});

describe('the decrypted export', () => {
  it('mirrors each line without key material, the plaintext where the ciphertext was', () => {
    const item = { id: 'd', type: 'document', title: 'Notes', maintenanceKey: 'AAAA', content: 'BBBB' } as ExportItem;
    const child = { id: 'f', parent: 'd', wrappedKey: 'CCCC', file: 'att/f' } as ExportItem;

    expect(decryptedManifestLine({ item, ok: true, plaintext: bytes('hi') })).toEqual({ id: 'd', type: 'document', title: 'Notes', content: 'aGk=' });
    expect(decryptedManifestLine({ item: child, ok: true, plaintext: bytes('hi') })).toEqual({ id: 'f', parent: 'd', file: 'att/f' });
    expect(decryptedManifestLine({ item: child, ok: false, error: 'nope' })).toEqual({ id: 'f', parent: 'd', error: 'nope' });
  });

  it('writes the files first and the manifest last, with every result in it', async () => {
    async function* results(): AsyncGenerator<ItemResult> {
      yield { item: { id: 'f', parent: 'd', file: 'att/f' } as ExportItem, ok: true, plaintext: bytes('file') };
      yield { item: { id: 'g', parent: 'd', file: 'att/g' } as ExportItem, ok: false, error: 'nope' };
    }

    const entries = [];

    for await (const entry of decryptedExportEntries(results(), async () => undefined))
      entries.push({ path: entry.path, text: new TextDecoder().decode(entry.data) });

    expect(entries).toEqual([
      { path: 'att/f', text: 'file' },
      { path: MANIFEST_FILE, text: '{"id":"f","parent":"d","file":"att/f"}\n{"id":"g","parent":"d","error":"nope"}\n' },
    ]);
  });
});
