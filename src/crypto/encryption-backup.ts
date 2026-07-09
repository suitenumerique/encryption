/**
 * Public-key wire encoding for server registration, plus the browser-safe base64
 * helpers used across the crypto layer. The wire-format public-key blob carries a
 * single CRYPTO_VERSION prefix byte before the X-Wing public key.
 *
 * Note: there is deliberately NO full-private-key export here. Recovery is the
 * server vault unlocked by the recovery phrase (or device approval); a raw-key
 * blob would be a second, more dangerous secret and is not offered.
 */
import type { HybridKeyPair, HybridPublicKey } from '@encryption/src/crypto/encryption';
import type { SignatureKeyPair } from '@encryption/src/crypto/signature';
import { CRYPTO_VERSION } from '@encryption/src/shared/constants';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

/**
 * Everything a device needs to BE a given identity: the encryption key pair
 * (X-Wing) plus the signature key pair (Ed25519, the identity). They live
 * together because losing one means losing the other, and a restored device must
 * reproduce the SAME identity fingerprint that contacts verified out-of-band.
 */
export interface UserKeyBundle {
  encryption: HybridKeyPair;
  signature: SignatureKeyPair;
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
 * Deserialize a public key from its raw wire bytes (`[version:1][key]`),
 * stripping the version byte. Used server-side now that keys are stored as
 * `Bytes` rather than base64.
 */
export function importPublicKeyFromBytes(blob: Uint8Array): HybridPublicKey {
  if (blob.length < 2) {
    throw new VaultError(VaultErrorCode.INVALID_BACKUP, 'Invalid public key: payload too short');
  }

  const version = blob[0];

  if (version !== CRYPTO_VERSION) {
    throw new VaultError(VaultErrorCode.UNSUPPORTED_CRYPTO_VERSION, `Unsupported crypto version ${version} in public key`);
  }

  return blob.slice(1);
}

/**
 * Deserialize an X-Wing public key from the base64 server format.
 */
export function importPublicKeyFromBase64(base64: string): HybridPublicKey {
  return importPublicKeyFromBytes(base64ToUint8(base64));
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
