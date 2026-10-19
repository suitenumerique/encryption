import { crc32 as nodeCrc32 } from 'node:zlib';
import { describe, expect, it } from 'vitest';

import { readZip } from '@encryption/src/maintenance/testing';
import { ZipLimitError, ZipWriter, crc32 } from '@encryption/src/maintenance/zip';

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

    for (const [path, data] of Object.entries(files)) zip.add(path, data);

    const entries = readZip(concat(zip.finish()));

    expect(entries.map((entry) => entry.name)).toEqual(Object.keys(files));

    for (const entry of entries) {
      expect(entry.data).toEqual(files[entry.name as keyof typeof files]);
      expect(entry.crc).toBe(nodeCrc32(entry.data));
      expect(entry.flags & 0x0800).toBe(0x0800);
    }
  });

  it('refuses a path twice, and says to split the export past the entry limit', () => {
    const zip = new ZipWriter();

    zip.add('a', new Uint8Array(1));
    expect(() => zip.add('a', new Uint8Array(1))).toThrow(/twice/);

    const full = new ZipWriter();

    for (let i = 0; i < 0xffff; i++) full.add(`f${i}`, new Uint8Array(0));
    expect(() => full.add('one-more', new Uint8Array(0))).toThrow(ZipLimitError);
  });
});
