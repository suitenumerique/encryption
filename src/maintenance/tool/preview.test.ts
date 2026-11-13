import { describe, expect, it } from 'vitest';

import { SAMPLE_IMAGES } from '@encryption/src/maintenance/testing';
import { previewOf } from '@encryption/src/maintenance/tool/preview';

const bytes = (s: string) => new TextEncoder().encode(s);

describe('previewOf', () => {
  it('shows text as text, accents and line breaks included, and only its beginning when long', () => {
    expect(previewOf(bytes('Été\n\tligne'))).toEqual({ kind: 'text', text: 'Été\n\tligne', truncated: false });
    expect(previewOf(bytes('a'.repeat(20_001)))).toMatchObject({ kind: 'text', truncated: true });
  });

  it('recognises images by their first bytes', () => {
    expect(previewOf(SAMPLE_IMAGES.red)).toEqual({ kind: 'image', mime: 'image/png' });
    expect(previewOf(Uint8Array.from([0xff, 0xd8, 0xff, 0xe0]))).toEqual({ kind: 'image', mime: 'image/jpeg' });
  });

  it('describes binary content, valid UTF-8 with control characters included (a Yjs update)', () => {
    expect(previewOf(Uint8Array.from([1, 2, 0, 65]))).toEqual({ kind: 'binary', format: 'unknown', size: 4, head: '01 02 00 41' });
    expect(previewOf(bytes('%PDF-1.7'))).toMatchObject({ kind: 'text' });
    expect(previewOf(Uint8Array.from([...bytes('%PDF-1.7\n'), 0xe2, 0xe3]))).toMatchObject({ kind: 'binary', format: 'pdf' });
    expect(previewOf(Uint8Array.from([0x50, 0x4b, 0x03, 0x04, 0]))).toMatchObject({ kind: 'binary', format: 'zip' });
  });
});
