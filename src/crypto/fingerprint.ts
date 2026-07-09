/**
 * Compute a 128-bit DECIMAL fingerprint of a public key using libsodium.
 * Accepts either a base64-encoded string or an ArrayBuffer.
 * Returns 40 decimal digits, zero-padded to a fixed width so the same key
 * always produces the exact same string. Storage format: "00317...".
 *
 * This matches `deviceKeyDecimalFingerprint` (device pairing): SHA-256 of the
 * key, first 16 bytes read big-endian as a BigInt, rendered as fixed-width
 * decimal. 128 bits is well beyond a grinding server's reach (2^128), and the
 * all-digits form is easy to read out and type during out-of-band verification.
 *
 * Uses libsodium (crypto_hash_sha256) for consistency — all crypto
 * operations go through libsodium via the vault (data.encryption).
 */
import sodium from 'libsodium-wrappers-sumo';

import { formatDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

// 128 bits of the SHA-256 of the public key, rendered as decimal digits.
const FINGERPRINT_BYTES = 16;
// A 128-bit value is at most 39 digits, so padding to 40 groups evenly into 8
// blocks of 5 and keeps a stable width (the leading digit is always 0).
const FINGERPRINT_DIGITS = 40;

export async function computeKeyFingerprint(key: string | ArrayBuffer): Promise<string> {
  await sodium.ready;

  const raw = key instanceof ArrayBuffer ? new Uint8Array(key) : Uint8Array.from(atob(key), (c) => c.charCodeAt(0));

  const hash = sodium.crypto_hash_sha256(raw).slice(0, FINGERPRINT_BYTES);

  let n = 0n;
  for (const b of hash) n = (n << 8n) | BigInt(b);

  return n.toString().padStart(FINGERPRINT_DIGITS, '0');
}

/**
 * Format a raw decimal fingerprint for display, grouped in blocks of five.
 * Delegates to the shared helper so vault and UI render it identically.
 */
export { formatDecimalFingerprint as formatFingerprint };
