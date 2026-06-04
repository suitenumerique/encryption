/**
 * Key backup and restoration for X-Wing key pairs.
 *
 * Keys are serialized as JSON containing base64-encoded raw bytes,
 * then the JSON is base64url-encoded as a "passphrase" string
 * compact enough to store in a password manager.
 *
 * The wire-format public-key blob (used for server registration) carries
 * a single CRYPTO_VERSION prefix byte before the X-Wing public key.
 * The backup JSON carries the same version in a top-level `version` field
 * so future migrations can dispatch on it.
 *
 * SECURITY NOTE: The backup contains the full X-Wing secret key (not a seed).
 * Using a seed to derive the key was considered but rejected:
 * - X-Wing's IND-CCA security argument is parameterized by the underlying
 *   randomness; using a user-chosen seed would weaken it to the seed's
 *   entropy and lose the hybrid's independent-compromise property.
 * - With the full secret key, X25519 and ML-KEM-768 keep independent
 *   security margins.
 * - The tradeoff is a longer passphrase (~3-4 KB encoded), but it can be
 *   saved as a file or copied into a password manager. The mnemonic
 *   (24 BIP-39 words) is reserved for device transfer, where the
 *   ephemeral symmetric key it encodes stays short.
 */
import type { HybridKeyPair, HybridPublicKey } from '@encryption/src/crypto/encryption';
import { CRYPTO_VERSION } from '@encryption/src/shared/constants';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

// ============================================================================
// Serialization: key pair → JSON → passphrase
// ============================================================================

interface SerializedKeyPair {
  version: number;
  publicKey: string; // base64 of the X-Wing public key bytes
  secretKey: string; // base64 of the X-Wing secret key bytes
}

export function keyPairToPassphrase(keyPair: HybridKeyPair): string {
  const serialized: SerializedKeyPair = {
    version: CRYPTO_VERSION,
    publicKey: uint8ToBase64(keyPair.publicKey),
    secretKey: uint8ToBase64(keyPair.secretKey),
  };

  const json = JSON.stringify(serialized);

  return uint8ToBase64Url(new TextEncoder().encode(json));
}

export function passphraseToKeyPair(passphrase: string): HybridKeyPair {
  const json = new TextDecoder().decode(base64UrlToUint8(passphrase));

  let parsed: unknown;

  try {
    parsed = JSON.parse(json);
  } catch {
    throw new VaultError(VaultErrorCode.INVALID_BACKUP, 'Invalid backup: corrupted or incompatible key format');
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new VaultError(VaultErrorCode.INVALID_BACKUP, 'Invalid backup: corrupted or incompatible key format');
  }

  const serialized = parsed as Record<string, unknown>;

  if (typeof serialized.publicKey !== 'string' || typeof serialized.secretKey !== 'string') {
    throw new VaultError(VaultErrorCode.INVALID_BACKUP, 'Invalid backup: corrupted or incompatible key format');
  }

  // Reject any backup that doesn't carry the version this build understands —
  // a legacy decode path can be added here when CRYPTO_VERSION bumps.
  if (serialized.version !== CRYPTO_VERSION) {
    throw new VaultError(VaultErrorCode.UNSUPPORTED_CRYPTO_VERSION, `Unsupported crypto version ${String(serialized.version)} in backup`);
  }

  const publicKey = base64ToUint8(serialized.publicKey);
  const secretKey = base64ToUint8(serialized.secretKey);

  return {
    publicKey,
    secretKey,
  };
}

// ============================================================================
// Public key export for server registration
// ============================================================================

/**
 * Serialize an X-Wing public key to a base64 string for server storage.
 * Wire format: [version:1][xwingPublicKey:1216].
 */
export function exportPublicKeyAsBase64(publicKey: HybridPublicKey): string {
  const blob = new Uint8Array(1 + publicKey.length);
  blob[0] = CRYPTO_VERSION;
  blob.set(publicKey, 1);

  return uint8ToBase64(blob);
}

/**
 * Deserialize an X-Wing public key from the base64 server format.
 */
export function importPublicKeyFromBase64(base64: string): HybridPublicKey {
  const blob = base64ToUint8(base64);

  if (blob.length < 2) {
    throw new VaultError(VaultErrorCode.INVALID_BACKUP, 'Invalid public key: payload too short');
  }

  const version = blob[0];

  if (version !== CRYPTO_VERSION) {
    throw new VaultError(VaultErrorCode.UNSUPPORTED_CRYPTO_VERSION, `Unsupported crypto version ${version} in public key`);
  }

  return blob.slice(1);
}

// ============================================================================
// Base64 helpers (browser-compatible, no Node Buffer)
// ============================================================================

export function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';

  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary);
}

export function base64ToUint8(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function uint8ToBase64Url(bytes: Uint8Array): string {
  return uint8ToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToUint8(base64url: string): Uint8Array {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');

  return base64ToUint8(base64);
}
