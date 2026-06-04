import { type HybridPublicKey, type HybridSecretKey, exportPublicKeyAsBase64, getEncryptionDB } from '@encryption/src/crypto';
import { STORE_KEY_PAIRS } from '@encryption/src/shared/constants';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

interface StoredKeyPair {
  publicKey: HybridPublicKey;
  secretKey: HybridSecretKey;
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

export async function handleHasKeys(userId: string): Promise<{ hasKeys: boolean }> {
  const pair = await getStoredKeyPair(userId);

  return { hasKeys: !!pair };
}

export async function handleGetPublicKey(userId: string): Promise<{ publicKey: ArrayBuffer }> {
  const pair = await getStoredKeyPair(userId);

  if (!pair) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'No key pair found. Generate keys first.');
  }

  const publicKeyBase64 = exportPublicKeyAsBase64(pair.publicKey);

  // Convert base64 to ArrayBuffer — products receive binary, not encoded strings
  const binary = atob(publicKeyBase64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return { publicKey: bytes.buffer as ArrayBuffer };
}
