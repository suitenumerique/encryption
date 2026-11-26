import { describe, expect, it } from 'vitest';

import { DOMAIN_DEVICE_PAIRING_FINGERPRINT, DOMAIN_IDENTITY_FINGERPRINT } from '@encryption/src/shared/crypto-domains';
import { computeDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

// Known-answer vectors: the vault, the interface and the SDK all compute these,
// and people compare them across devices, so the scheme must never drift.
describe('computeDecimalFingerprint (known answers)', () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => i);

  it('matches the identity vector', async () => {
    expect(await computeDecimalFingerprint(DOMAIN_IDENTITY_FINGERPRINT, key)).toBe('1307400058327233257599020659189704828291');
  });

  it('matches the device-pairing vector, distinct from the identity one for the same key', async () => {
    expect(await computeDecimalFingerprint(DOMAIN_DEVICE_PAIRING_FINGERPRINT, key)).toBe('1031513360135392777772310194262846940559');
  });
});
