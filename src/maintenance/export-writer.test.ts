import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import { type ExportItem, MANIFEST_FILE } from '@encryption/src/maintenance/export-format';
import { type ItemOutcome, folderSink, memorySpool, writeDecryptedExport, zipSink } from '@encryption/src/maintenance/export-writer';
import { type ItemResult } from '@encryption/src/maintenance/recover';
import { mapSink, memoryDirectory, memoryFile, readZip } from '@encryption/src/maintenance/testing';

const bytes = (text: string) => new TextEncoder().encode(text);
const text = (data: Uint8Array | undefined) => new TextDecoder().decode(data);

async function* results(): AsyncGenerator<ItemResult> {
  yield { item: { id: 'd', type: 'document', maintenanceKey: 'AAAA', content: 'BBBB' } as ExportItem, ok: true, plaintext: bytes('the document') };
  yield { item: { id: 'f', parent: 'd', wrappedKey: 'CCCC', file: 'att/f.png' } as ExportItem, ok: true, plaintext: bytes('the picture') };
  yield { item: { id: 'g', parent: 'd', file: 'att/g.png' } as ExportItem, ok: false, error: 'file att/g.png is not in the export folder' };
  yield { item: { id: 'x', maintenanceKey: 'DDDD', title: 'Theirs' } as ExportItem, ok: false, error: 'elsewhere', otherKey: '1234' };
  yield { item: { id: 'y', parent: 'x', file: 'att/y.png' } as ExportItem, ok: false, error: 'elsewhere', otherKey: '1234' };
}

const readFile = async (path: string) => (path === 'att/y.png' ? bytes('still sealed') : undefined);

// The folder every sink must produce, whatever it stores it in.
const EXPECTED = {
  'att/f.png': 'the picture',
  'other-keys/1234/att/y.png': 'still sealed',
  'other-keys/1234/manifest.ndjson': '{"id":"x","maintenanceKey":"DDDD","title":"Theirs"}\n{"id":"y","parent":"x","file":"att/y.png"}\n',
  [MANIFEST_FILE]:
    '{"id":"d","type":"document","content":"dGhlIGRvY3VtZW50"}\n{"id":"f","parent":"d","file":"att/f.png"}\n{"id":"g","parent":"d","error":"file att/g.png is not in the export folder"}\n',
};

const asText = (files: Map<string, Uint8Array>) => Object.fromEntries([...files].map(([path, data]) => [path, text(data)]));

describe('writeDecryptedExport', () => {
  it("writes each plaintext as it comes, sets other keys' items aside, and keeps only outcomes", async () => {
    const sink = mapSink();
    const outcomes: ItemOutcome[] = [];

    await writeDecryptedExport(results(), readFile, sink, (outcome) => outcomes.push(outcome));

    expect(asText(sink.files)).toEqual(EXPECTED);
    expect(outcomes.map((outcome) => [outcome.item.id, outcome.ok, outcome.size])).toEqual([
      ['d', true, 12],
      ['f', true, 11],
      ['g', false, undefined],
      ['x', false, undefined],
      ['y', false, undefined],
    ]);
    expect(outcomes.some((outcome) => 'plaintext' in outcome)).toBe(false);
  });

  it('writes a folder of plain files through directory handles', async () => {
    const directory = memoryDirectory();

    await writeDecryptedExport(results(), readFile, folderSink(directory));

    expect(asText(directory.files)).toEqual(EXPECTED);
  });

  it('streams a ZIP archive whose manifests, spooled aside, come last, readable by this reader and by Python', async () => {
    const output = memoryFile();

    await writeDecryptedExport(
      results(),
      readFile,
      zipSink(output, async () => memorySpool(), new Date(2026, 9, 19))
    );

    const archive = output.bytes();
    const entries = readZip(archive);

    expect(output.closed).toBe(true);
    expect(Object.fromEntries(entries.map((entry) => [entry.name, text(entry.data)]))).toEqual(EXPECTED);
    expect(entries.at(-1)?.name).toBe(MANIFEST_FILE);

    const path = resolve(mkdtempSync(resolve(tmpdir(), 'export-zip-')), 'export.zip');

    writeFileSync(path, archive);
    expect(
      execFileSync(
        'python3',
        ['-I', '-c', 'import sys, zipfile; z = zipfile.ZipFile(sys.argv[1]); print(z.testzip(), z.read("manifest.ndjson").count(b"\\n"))', path],
        {
          encoding: 'utf8',
        }
      ).trim()
    ).toBe('None 3');
  });
});
