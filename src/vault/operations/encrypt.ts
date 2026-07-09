import { encryptContent, encryptSymmetricKeyForUsers, generateSymmetricKey, importPublicKeyFromBase64, uint8ToBase64 } from '@encryption/src/crypto';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { getStoredKeyPair } from '@encryption/src/vault/operations/key-management';
import { resolveKeyChain, resolveSymmetricKey } from '@encryption/src/vault/operations/symmetric-key-utils';

/**
 * Mint a fresh symmetric key and encrypt `data` with it.
 * Shared by the two "create" operations (root and nested): both mint a new
 * key and encrypt the payload identically, then diverge only in how the
 * freshly-minted key is wrapped.
 */
async function mintKeyAndEncrypt(data: ArrayBuffer): Promise<{ newKey: Uint8Array; encryptedContent: ArrayBuffer }> {
  const newKey = await generateSymmetricKey();
  const dataBytes = new Uint8Array(data);
  const encrypted = await encryptContent(dataBytes, newKey);
  return {
    newKey,
    encryptedContent: encrypted.buffer as ArrayBuffer,
  };
}

/**
 * Encrypt content with an EXISTING symmetric key — purely symmetric.
 *
 * Without `encryptedKeyChain`: resolve the entry key (asymmetric unwrap with
 * the user's private key) and encrypt with it. Used by the flat model (Docs).
 *
 * With `encryptedKeyChain`: resolve entry + chain to the terminal symmetric
 * key and encrypt with it. Symmetric mirror of `decryptWithKey`. Used by the
 * collaborative relay and any caller that wants to encrypt with a key that
 * already exists somewhere in the hierarchy.
 *
 * This operation does NOT mint a new key. To create a new encrypted resource,
 * use `handleEncryptWithoutKey` (new root) or `handleEncryptNestedWithoutKey`
 * (new child inside an existing encrypted subtree).
 */
export async function handleEncryptWithKey(
  userId: string,
  payload: {
    data: ArrayBuffer;
    encryptedSymmetricKey: ArrayBuffer;
    encryptedKeyChain?: ArrayBuffer[];
  }
): Promise<{ encryptedData: ArrayBuffer }> {
  const encryptedKey = new Uint8Array(payload.encryptedSymmetricKey);
  const dataBytes = new Uint8Array(payload.data);

  const symmetricKey =
    payload.encryptedKeyChain && payload.encryptedKeyChain.length > 0
      ? await resolveKeyChain(
          userId,
          encryptedKey,
          payload.encryptedKeyChain.map((buf) => new Uint8Array(buf))
        )
      : await resolveSymmetricKey(userId, encryptedKey);

  const encrypted = await encryptContent(dataBytes, symmetricKey);

  return { encryptedData: encrypted.buffer as ArrayBuffer };
}

/**
 * Create a NEW root resource. Mint K_new, encrypt `data` with K_new, and
 * wrap K_new once per user under that user's public key.
 *
 * Used for standalone encrypted files (no parent) and for the root folder
 * of an encrypted subtree. Callers persist each returned wrapped key on the
 * matching user's access row.
 */
export async function handleEncryptWithoutKey(
  userId: string,
  payload: { data: ArrayBuffer; userPublicKeys: Record<string, ArrayBuffer> }
): Promise<{ encryptedContent: ArrayBuffer; encryptedKeys: Record<string, ArrayBuffer> }> {
  const pair = await getStoredKeyPair(userId);

  if (!pair) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'No key pair found. Generate keys first.');
  }

  const { newKey, encryptedContent } = await mintKeyAndEncrypt(payload.data);

  const usersPublicKeys: Record<string, import('@encryption/src/crypto').HybridPublicKey> = {};

  for (const [uid, keyBuffer] of Object.entries(payload.userPublicKeys)) {
    const base64Key = uint8ToBase64(new Uint8Array(keyBuffer));
    usersPublicKeys[uid] = importPublicKeyFromBase64(base64Key);
  }

  const encryptedKeysRaw = await encryptSymmetricKeyForUsers(newKey, usersPublicKeys);
  const encryptedKeys: Record<string, ArrayBuffer> = {};

  for (const [uid, encKey] of Object.entries(encryptedKeysRaw)) {
    encryptedKeys[uid] = encKey.buffer as ArrayBuffer;
  }

  return { encryptedContent, encryptedKeys };
}

/**
 * Create a NEW nested resource inside an existing encrypted subtree. Resolve
 * entry + chain to the parent folder's key K_parent, mint K_new, encrypt
 * `data` with K_new, and wrap K_new under K_parent.
 *
 * Used for creating a new file inside an already-encrypted folder. Callers
 * persist the returned `wrappedKey` on the new item's DB row — it becomes
 * the first link the hierarchy uses to later resolve K_new when reading.
 */
export async function handleEncryptNestedWithoutKey(
  userId: string,
  payload: {
    data: ArrayBuffer;
    encryptedSymmetricKey: ArrayBuffer;
    encryptedKeyChain?: ArrayBuffer[];
  }
): Promise<{ encryptedContent: ArrayBuffer; wrappedKey: ArrayBuffer }> {
  const encryptedKey = new Uint8Array(payload.encryptedSymmetricKey);
  const chain = (payload.encryptedKeyChain ?? []).map((buf) => new Uint8Array(buf));
  const parentKey = await resolveKeyChain(userId, encryptedKey, chain);

  const { newKey, encryptedContent } = await mintKeyAndEncrypt(payload.data);
  const wrappedKey = await encryptContent(newKey, parentKey);

  return {
    encryptedContent,
    wrappedKey: wrappedKey.buffer as ArrayBuffer,
  };
}
