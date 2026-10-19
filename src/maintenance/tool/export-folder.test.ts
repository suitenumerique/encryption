import { describe, expect, it } from 'vitest';

import { openExportFolder } from '@encryption/src/maintenance/tool/export-folder';

const picked = (files: Record<string, string>) =>
  Object.entries(files).map(([path, text]) => ({ path, read: async () => new TextEncoder().encode(text) }));

describe('openExportFolder', () => {
  it('takes the picked folder as the root, with paths relative to it', async () => {
    const folder = await openExportFolder(picked({ 'export/manifest.ndjson': '{}', 'export/attachments/d/a': 'bytes' }));

    expect(folder).toMatchObject({ name: 'export', manifest: '{}', fileCount: 1 });
    expect(new TextDecoder().decode(await folder?.readFile('attachments/d/a'))).toBe('bytes');
    expect(await folder?.readFile('export/attachments/d/a')).toBeUndefined();
    expect([folder?.hasFile('attachments/d/a'), folder?.hasFile('attachments/d/b')]).toEqual([true, false]);
  });

  it('also finds the export one level down, and ignores what sits beside it', async () => {
    const folder = await openExportFolder(
      picked({ 'usb/export/manifest.ndjson': '{}', 'usb/export/blob': 'x', 'usb/notes.txt': 'n', 'usb/export/old/manifest.ndjson': 'old' })
    );

    expect(folder).toMatchObject({ name: 'export', manifest: '{}', fileCount: 2 });
    expect(await folder?.readFile('../notes.txt')).toBeUndefined();
  });

  it('says there is nothing to open without a manifest', async () => {
    expect(await openExportFolder(picked({ 'export/blob': 'x' }))).toBeNull();
  });
});
