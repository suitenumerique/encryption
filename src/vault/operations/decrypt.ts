import { decryptContent } from '@encryption/src/crypto';
import { resolveKeyChain, resolveSymmetricKey } from '@encryption/src/vault/operations/symmetric-key-utils';

/**
 * Decrypt content using a separately provided encrypted symmetric key.
 * Used for multi-user documents where each user has their own encrypted
 * copy of the symmetric key.
 *
 * Supports an optional `encryptedKeyChain` for Drive's key hierarchy:
 * when provided, the entry-point key is first resolved via chain unwrapping
 * before being used to decrypt the content.
 *
 * All data is transferred as ArrayBuffer for zero-copy performance.
 * The symmetric key decryption result is cached per session.
 */
export async function handleDecryptWithKey(
  userId: string,
  payload: {
    encryptedData: ArrayBuffer;
    encryptedSymmetricKey: ArrayBuffer;
    encryptedKeyChain?: ArrayBuffer[];
  }
): Promise<{ data: ArrayBuffer }> {
  const encryptedContent = new Uint8Array(payload.encryptedData);
  const encryptedKey = new Uint8Array(payload.encryptedSymmetricKey);

  let symmetricKey: Uint8Array;

  if (payload.encryptedKeyChain && payload.encryptedKeyChain.length > 0) {
    // Drive key hierarchy: resolve the chain from entry point to target
    const chain = payload.encryptedKeyChain.map((buf) => new Uint8Array(buf));
    symmetricKey = await resolveKeyChain(userId, encryptedKey, chain);
  } else {
    // Docs flat model: direct key resolution
    symmetricKey = await resolveSymmetricKey(userId, encryptedKey);
  }

  const decrypted = await decryptContent(encryptedContent, symmetricKey);

  return { data: decrypted.buffer as ArrayBuffer };
}
