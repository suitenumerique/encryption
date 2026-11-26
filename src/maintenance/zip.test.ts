import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { crc32 as nodeCrc32 } from 'node:zlib';
import { describe, expect, it } from 'vitest';

import { readZip } from '@encryption/src/maintenance/testing';
import { ZipWriter, crc32 } from '@encryption/src/maintenance/zip';

const concat = (parts: Uint8Array[]) => Uint8Array.from(parts.flatMap((part) => [...part]));

describe('ZipWriter', () => {
  it('computes the same CRC-32 as zlib', () => {
    for (const sample of [new Uint8Array(0), new TextEncoder().encode('bonjour'), Uint8Array.from({ length: 5000 }, (_, i) => (i * 31) & 0xff)]) {
      expect(crc32(sample)).toBe(nodeCrc32(sample));
    }
  });

  it('writes an archive whose directory, headers and checksums agree, with UTF-8 names in folders', () => {
    const zip = new ZipWriter(new Date(2026, 9, 19, 14, 30, 10));
    const files = {
      'manifest.ndjson': new TextEncoder().encode('{"id":"a"}\n'),
      'attachments/doc-1/pièce jointe.png': Uint8Array.from([0x89, 0x50, 0x4e, 0x47]),
      empty: new Uint8Array(0),
    };

    const parts = Object.entries(files).flatMap(([path, data]) => zip.add(path, data));
    const entries = readZip(concat([...parts, ...zip.finish()]));

    expect(entries.map((entry) => entry.name)).toEqual(Object.keys(files));

    for (const entry of entries) {
      expect(entry.data).toEqual(files[entry.name as keyof typeof files]);
      expect(entry.crc).toBe(nodeCrc32(entry.data));
      expect(entry.flags & 0x0800).toBe(0x0800);
    }
  });

  it('refuses a path twice', () => {
    const zip = new ZipWriter();

    zip.add('a', new Uint8Array(1));
    expect(() => zip.add('a', new Uint8Array(1))).toThrow(/twice/);
  });

  // ZIP64 starts past 4 GiB or 65,535 entries, which a test cannot write: the limits
  // are lowered to zero, so every size, offset and count goes through its ZIP64 form.
  it('switches to ZIP64 past the limits, in a form both this reader and Python read', () => {
    const zip = new ZipWriter(new Date(2026, 9, 19), { bytes: 0, entries: 0 });
    const files = { 'manifest.ndjson': new TextEncoder().encode('{"id":"a"}\n'), 'a/b.bin': Uint8Array.from({ length: 300 }, (_, i) => i & 0xff) };
    const archive = concat([...Object.entries(files).flatMap(([path, data]) => zip.add(path, data)), ...zip.finish()]);

    expect(readZip(archive).map((entry) => [entry.name, entry.data])).toEqual(Object.entries(files));

    const path = resolve(mkdtempSync(resolve(tmpdir(), 'zip64-')), 'archive.zip');

    writeFileSync(path, archive);
    expect(
      execFileSync('python3', ['-I', '-c', 'import sys, zipfile; z = zipfile.ZipFile(sys.argv[1]); print(z.testzip(), sorted(z.namelist()))', path], {
        encoding: 'utf8',
      }).trim()
    ).toBe("None ['a/b.bin', 'manifest.ndjson']");
  });
});
