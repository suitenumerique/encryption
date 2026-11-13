/**
 * The identity fingerprint people verify out of band: the decimal fingerprint of
 * the identity (signature) public key wire blob, under the identity domain. See
 * `computeDecimalFingerprint` for the scheme. Accepts the key as base64 or bytes.
 */
import { base64ToUint8 } from '@encryption/src/crypto/encryption-backup';
import { DOMAIN_IDENTITY_FINGERPRINT } from '@encryption/src/shared/crypto-domains';
import { computeDecimalFingerprint, formatDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

export async function computeKeyFingerprint(key: string | ArrayBuffer): Promise<string> {
  const raw = key instanceof ArrayBuffer ? new Uint8Array(key) : base64ToUint8(key);

  return computeDecimalFingerprint(DOMAIN_IDENTITY_FINGERPRINT, raw);
}

/**
 * Format a raw decimal fingerprint for display, grouped in blocks of five.
 * Delegates to the shared helper so vault and UI render it identically.
 */
export { formatDecimalFingerprint as formatFingerprint };
