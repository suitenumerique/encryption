import {
  encryptSymmetricKeyForUsers,
  importPublicKeyFromBase64,
  uint8ToBase64,
} from '@encryption/src/crypto';
import { resolveKeyChain, resolveSymmetricKey } from '@encryption/src/vault/operations/symmetric-key-utils';

/**
 * Share an existing document's or item's symmetric key with additional users.
 *
 * Accepts a map of user IDs → public keys (same signature as encryptWithoutKey).
 * For each user:
 * 1. Decrypts the current user's copy of the symmetric key (cached)
 * 2. Re-encrypts it with each target user's public key
 * 3. Returns a map of user ID → encrypted symmetric key
 *
 * Supports an optional `encryptedKeyChain` for Drive's key hierarchy:
 * when provided, resolves the chain from the user's entry-point key down
 * to the target item's key before re-encrypting for the target users.
 *
 * The raw symmetric key never leaves the vault iframe.
 */
export async function handleShareKeys(
  userId: string,
  payload: {
    encryptedSymmetricKey: ArrayBuffer;
    userPublicKeys: Record<string, ArrayBuffer>;
    encryptedKeyChain?: ArrayBuffer[];
  },
): Promise<{ encryptedKeys: Record<string, ArrayBuffer> }> {
  const encryptedKey = new Uint8Array(payload.encryptedSymmetricKey);

  let symmetricKey: Uint8Array;

  if (payload.encryptedKeyChain && payload.encryptedKeyChain.length > 0) {
    // Drive key hierarchy: resolve the chain to get the target item's key
    const chain = payload.encryptedKeyChain.map((buf) => new Uint8Array(buf));
    symmetricKey = await resolveKeyChain(userId, encryptedKey, chain);
  } else {
    // Docs flat model: direct key resolution
    symmetricKey = await resolveSymmetricKey(userId, encryptedKey);
  }

  // Convert ArrayBuffer public keys to internal format
  const usersPublicKeys: Record<string, import('@encryption/src/crypto').HybridPublicKey> = {};

  for (const [uid, keyBuffer] of Object.entries(payload.userPublicKeys)) {
    const base64Key = uint8ToBase64(new Uint8Array(keyBuffer as ArrayBuffer));
    usersPublicKeys[uid] = importPublicKeyFromBase64(base64Key);
  }

  const encryptedKeysRaw = await encryptSymmetricKeyForUsers(symmetricKey, usersPublicKeys);

  const encryptedKeys: Record<string, ArrayBuffer> = {};

  for (const [uid, encKey] of Object.entries(encryptedKeysRaw)) {
    encryptedKeys[uid] = encKey.buffer as ArrayBuffer;
  }

  return { encryptedKeys };
}
