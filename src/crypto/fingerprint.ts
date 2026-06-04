/**
 * Compute a SHA-256 fingerprint of a public key using libsodium.
 * Accepts either a base64-encoded string or an ArrayBuffer.
 * Returns 16 lowercase hex characters (no spaces, no uppercase).
 * Storage format: "a1b2c3d4e5f67890"
 *
 * Uses libsodium (crypto_hash_sha256) for consistency — all crypto
 * operations go through libsodium via the vault (data.encryption).
 */
import sodium from 'libsodium-wrappers-sumo';

export async function computeKeyFingerprint(key: string | ArrayBuffer): Promise<string> {
  await sodium.ready;

  const raw = key instanceof ArrayBuffer
    ? new Uint8Array(key)
    : Uint8Array.from(atob(key), (c) => c.charCodeAt(0));

  const hash = sodium.crypto_hash_sha256(raw);

  return Array.from(hash)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 16);
}

/**
 * Format a raw fingerprint for display: "a1b2c3d4e5f67890" → "A1B2 C3D4 E5F6 7890"
 */
export function formatFingerprint(fingerprint: string): string {
  return fingerprint
    .replace(/(.{4})/g, '$1 ')
    .trim()
    .toUpperCase();
}
