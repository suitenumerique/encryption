import { computeKeyFingerprint, formatFingerprint } from '@encryption/src/crypto/fingerprint';

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
