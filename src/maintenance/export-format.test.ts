import { describe, expect, it } from 'vitest';

import { ManifestError, parseManifest } from '@encryption/src/maintenance/export-format';

const lines = (...items: unknown[]) => items.map((item) => JSON.stringify(item)).join('\n');

describe('parseManifest', () => {
  it('reads roots, wrapped children and children sharing their parent key, keeping the product fields', () => {
    const items = parseManifest(
      `${lines(
        { id: 'doc-1', type: 'document', maintenanceKey: 'AAAA', content: 'BBBB', title: 'Notes', updatedAt: '2026-10-19T10:00:00Z' },
        { id: 'att-1', type: 'attachment', parent: 'doc-1', wrappedKey: 'CCCC', file: 'attachments/doc-1/att-1' },
        { id: 7, type: 'comment', parent: 'doc-1', content: 'DDDD' },
        { id: 'folder', maintenanceKey: 'EEEE' }
      )}\r\n\r\n`
    );

    expect(items).toEqual([
      { id: 'doc-1', type: 'document', maintenanceKey: 'AAAA', content: 'BBBB', title: 'Notes', updatedAt: '2026-10-19T10:00:00Z' },
      { id: 'att-1', type: 'attachment', parent: 'doc-1', wrappedKey: 'CCCC', file: 'attachments/doc-1/att-1' },
      { id: 7, type: 'comment', parent: 'doc-1', content: 'DDDD' },
      { id: 'folder', maintenanceKey: 'EEEE' },
    ]);
  });

  it.each([
    ['no key source', { id: 'a', content: 'AAAA' }, /exactly one of maintenanceKey/],
    ['two key sources', { id: 'a', maintenanceKey: 'AAAA', parent: 'b' }, /exactly one of maintenanceKey/],
    ['a wrapped key without parent', { id: 'a', maintenanceKey: 'AAAA', wrappedKey: 'BBBB' }, /parent is required/],
    ['two places for the ciphertext', { id: 'a', maintenanceKey: 'AAAA', content: 'BBBB', file: 'x' }, /give one/],
    ['a path leaving the folder', { id: 'a', maintenanceKey: 'AAAA', file: '../etc/passwd' }, /relative path/],
    ['an absolute path', { id: 'a', maintenanceKey: 'AAAA', file: '/etc/passwd' }, /relative path/],
    ['the manifest as a file', { id: 'a', maintenanceKey: 'AAAA', file: 'manifest.ndjson' }, /cannot be an item's file/],
    ['a path in the folder set aside for other keys', { id: 'a', maintenanceKey: 'AAAA', file: 'other-keys/1234/x' }, /other keys' items/],
    ["PostgreSQL's wrapped base64", { id: 'a', maintenanceKey: `${'A'.repeat(76)}\n${'A'.repeat(4)}` }, /translate/],
  ])('refuses %s, naming the line', (_name, item, message) => {
    expect(() => parseManifest(lines({ id: 'ok', maintenanceKey: 'AAAA' }, item))).toThrow(message);
    expect(() => parseManifest(lines({ id: 'ok', maintenanceKey: 'AAAA' }, item))).toThrow(/^line 2: /);
  });

  it('refuses a line that is not JSON, an id given twice and a file named by two items', () => {
    expect(() => parseManifest('{"id":"a",')).toThrow(ManifestError);
    expect(() => parseManifest(lines({ id: 'a', maintenanceKey: 'AAAA' }, { id: 'a', parent: 'b' }))).toThrow(/line 2: id a appears twice/);
    expect(() => parseManifest(lines({ id: 7, maintenanceKey: 'AAAA' }, { id: '7', parent: 7 }))).toThrow(/line 2: id 7 appears twice/);
    expect(() => parseManifest(lines({ id: 'a', maintenanceKey: 'AAAA', file: 'blobs/x' }, { id: 'b', parent: 'a', file: 'Blobs/X' }))).toThrow(
      /line 2: file Blobs\/X is named by two items/
    );
  });
});
