import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { computeKeyFingerprint, formatFingerprint } from '@encryption/src/crypto/fingerprint';
import { formatDecimalFingerprint, normalizeDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

describe('computeKeyFingerprint', () => {
  it('should produce 40 decimal digits', async () => {
    const fingerprint = await computeKeyFingerprint(btoa('test-public-key-data'));

    expect(fingerprint).toMatch(/^\d{40}$/);
  });

  it('should produce different fingerprints for different keys', async () => {
    const fp1 = await computeKeyFingerprint(btoa('key-one'));
    const fp2 = await computeKeyFingerprint(btoa('key-two'));

    expect(fp1).not.toBe(fp2);
  });

  it('should be deterministic', async () => {
    const key = btoa('consistent-key');

    expect(await computeKeyFingerprint(key)).toBe(await computeKeyFingerprint(key));
  });

  it('should agree between base64 and ArrayBuffer inputs for the same key', async () => {
    const bytes = new TextEncoder().encode('same-key-material');
    const base64 = btoa(String.fromCharCode(...bytes));
    const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

    expect(await computeKeyFingerprint(base64)).toBe(await computeKeyFingerprint(buffer));
  });
});

describe('formatFingerprint', () => {
  it('should group 40 digits into blocks of five', () => {
    expect(formatFingerprint('0031700000000000000000000000000000000042')).toBe('00317 00000 00000 00000 00000 00000 00000 00042');
  });
});

describe('fingerprint format (property)', () => {
  it('is always 40 digits with a leading zero, for any key bytes', async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ minLength: 1, maxLength: 1300 }), async (bytes) => {
        const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
        const fingerprint = await computeKeyFingerprint(buffer);

        expect(fingerprint).toMatch(/^0\d{39}$/);
        expect(await computeKeyFingerprint(btoa(String.fromCharCode(...bytes)))).toBe(fingerprint);
      })
    );
  });

  it('survives display formatting and any user-typed separators', () => {
    const digits = fc.array(fc.integer({ min: 0, max: 9 }), { minLength: 40, maxLength: 40 }).map((d) => d.join(''));
    const separator = fc.constantFrom('', ' ', '-', '  ', '\u00a0', '.');

    fc.assert(
      fc.property(digits, separator, (d, sep) => {
        const formatted = formatDecimalFingerprint(d);

        expect(formatted.split(' ')).toHaveLength(8);
        expect(normalizeDecimalFingerprint(formatted)).toBe(d);
        expect(normalizeDecimalFingerprint(formatted.split(' ').join(sep))).toBe(d);
      })
    );
  });
});
