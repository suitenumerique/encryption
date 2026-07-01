import {
  type HybridPublicKey,
  type HybridSecretKey,
  type SignaturePublicKey,
  type SignatureSecretKey,
  type UserKeyBundle,
  exportPublicKeyAsBase64,
  getEncryptionDB,
} from '@encryption/src/crypto';
import { STORE_KEY_PAIRS } from '@encryption/src/shared/constants';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

/**
 * On-device key material for one identity. The encryption key keeps the
 * historical `publicKey`/`secretKey` field names (X-Wing); the signature
 * (identity) key pair sits alongside it. Both are written together by every
 * write path — generate, restore-from-backup, device transfer — so a stored
 * pair is never half-populated in practice. The signature fields are typed
 * optional only to model pre-signature local data that predates this feature;
 * the {@link getStoredKeyBundle} helper rejects such legacy rows with a clear
 * MISSING_KEYS error instead of letting `undefined` reach a sign call.
 */
interface StoredKeyPair {
  publicKey: HybridPublicKey;
  secretKey: HybridSecretKey;
  signaturePublicKey?: SignaturePublicKey;
  signatureSecretKey?: SignatureSecretKey;
}

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

export async function getStoredKeyPair(userId: string): Promise<StoredKeyPair | null> {
  const db = await getEncryptionDB();
  const pair = (await db.get(STORE_KEY_PAIRS, userId)) as StoredKeyPair | undefined;

  return pair ?? null;
}

/**
 * Read the full identity bundle (encryption + signature key pairs). Use this
 * everywhere both keys are needed (backup, device transfer, registration
 * signing). Throws MISSING_KEYS when no pair is stored OR when a stored pair
 * predates the signature feature — in both cases the user must re-onboard, and
 * a missing identity key must never silently degrade into "no signature".
 */
export async function getStoredKeyBundle(userId: string): Promise<UserKeyBundle> {
  const pair = await getStoredKeyPair(userId);

  if (!pair) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'No key pair found. Generate keys first.');
  }

  if (!pair.signaturePublicKey || !pair.signatureSecretKey) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'Stored keys predate the signature identity. Re-onboard to create an identity key.');
  }

  return {
    encryption: { publicKey: pair.publicKey, secretKey: pair.secretKey },
    signature: { publicKey: pair.signaturePublicKey, secretKey: pair.signatureSecretKey },
  };
}

export async function handleHasKeys(userId: string): Promise<{ hasKeys: boolean }> {
  const pair = await getStoredKeyPair(userId);

  return { hasKeys: !!pair };
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
 * encoded strings). `publicKey` is the encryption key (X-Wing); when the stored
 * identity includes a signature key, `signaturePublicKey` carries it too — the
 * identity key whose fingerprint contacts verify out-of-band.
 */
export async function handleGetPublicKey(userId: string): Promise<{ publicKey: ArrayBuffer; signaturePublicKey?: ArrayBuffer }> {
  const pair = await getStoredKeyPair(userId);

  if (!pair) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'No key pair found. Generate keys first.');
  }

  const publicKey = base64ToArrayBuffer(exportPublicKeyAsBase64(pair.publicKey));
  const signaturePublicKey = pair.signaturePublicKey ? base64ToArrayBuffer(exportPublicKeyAsBase64(pair.signaturePublicKey)) : undefined;

  return { publicKey, signaturePublicKey };
}
