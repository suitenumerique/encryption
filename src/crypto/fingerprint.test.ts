import { computeKeyFingerprint, formatFingerprint } from '@encryption/src/crypto/fingerprint';

describe('computeKeyFingerprint', () => {
  it('should produce 16 lowercase hex chars without spaces', async () => {
    const fingerprint = await computeKeyFingerprint(btoa('test-public-key-data'));

    expect(fingerprint).toMatch(/^[a-f0-9]{16}$/);
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
});

describe('formatFingerprint', () => {
  it('should format as uppercase groups of 4 with spaces', () => {
    expect(formatFingerprint('a1b2c3d4e5f67890')).toBe('A1B2 C3D4 E5F6 7890');
  });

  it('should handle already uppercase input', () => {
    expect(formatFingerprint('A1B2C3D4E5F67890')).toBe('A1B2 C3D4 E5F6 7890');
  });
});
