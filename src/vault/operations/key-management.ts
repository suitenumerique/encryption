import { type UserKeyBundle, exportPublicKeyAsBase64 } from '@encryption/src/crypto';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { type StoredKeyPair, deriveStoredKeyPair, hasVaultKeys, loadVault } from '@encryption/src/vault/vault-keys';

let operationQueue: Promise<unknown> = Promise.resolve();

/**
 * Serialize vault write operations to prevent concurrent IndexedDB access.
 * Read operations don't need serialization.
 */
export function serialized<T>(fn: () => Promise<T>): Promise<T> {
  const result = operationQueue.then(fn, fn); // Run even if previous failed
  operationQueue = result.then(
    () => {},
    () => {}
  ); // Swallow to not block queue
  return result;
}

/**
 * Which encryption key to project out of the vault:
 *   - a `number`: the exact retained key VERSION a wrap was produced against —
 *     used by the READ path, where the product passes the version it stored on
 *     the access row, so an old-version wrap keeps decrypting after a rotation.
 *   - `'active'`: the current active key — used by the WRITE paths (re-encrypt,
 *     share, (re)wrap) that operate on the live document. Exact while a single
 *     version exists; those call sites pass the stored version like the read
 *     path once key rotation is implemented.
 * The identity (signature) key is always the active one regardless.
 */
export type KeyVersionSelector = number | 'active';

/**
 * The identity's key material, projected out of the synchronized vault (sealed
 * items unwrapped with the device-cached VRK), with the ENCRYPTION key selected
 * by `version` (default `'active'`). Returns null when this device holds no
 * vault, or the requested encryption-key version is not held on it.
 */
export async function getStoredKeyPair(userId: string, version: KeyVersionSelector = 'active'): Promise<StoredKeyPair | null> {
  const loaded = await loadVault(userId);

  return loaded ? deriveStoredKeyPair(loaded.state, version) : null;
}

/**
 * Read the full identity bundle (encryption + signature key pairs). Use this
 * everywhere both keys are needed (backup, registration signing). Throws
 * MISSING_KEYS when no vault is present OR when the active key somehow has no
 * identity — a missing identity key must never silently degrade into "no
 * signature".
 */
export async function getStoredKeyBundle(userId: string): Promise<UserKeyBundle> {
  const pair = await getStoredKeyPair(userId);

  if (!pair) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'No key pair found. Generate keys first.');
  }

  return {
    encryption: { publicKey: pair.publicKey, secretKey: pair.secretKey },
    signature: { publicKey: pair.signaturePublicKey, secretKey: pair.signatureSecretKey },
  };
}

export async function handleHasKeys(userId: string): Promise<{ hasKeys: boolean }> {
  return { hasKeys: await hasVaultKeys(userId) };
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer as ArrayBuffer;
}

/**
 * Return the user's public keys as binary (products receive ArrayBuffers, not
 * encoded strings). `publicKey` is the encryption key (X-Wing); `signaturePublicKey`
 * is the identity key whose fingerprint contacts verify out-of-band.
 */
export async function handleGetPublicKey(userId: string): Promise<{ publicKey: ArrayBuffer; signaturePublicKey: ArrayBuffer }> {
  const pair = await getStoredKeyPair(userId);

  if (!pair) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'No key pair found. Generate keys first.');
  }

  const publicKey = base64ToArrayBuffer(exportPublicKeyAsBase64(pair.publicKey));
  const signaturePublicKey = base64ToArrayBuffer(exportPublicKeyAsBase64(pair.signaturePublicKey));

  return { publicKey, signaturePublicKey };
}
