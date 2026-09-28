import { decryptContent } from '@encryption/src/crypto';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
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
    keyVersion: number;
  }
): Promise<{ data: ArrayBuffer }> {
  const encryptedContent = new Uint8Array(payload.encryptedData);
  const encryptedKey = new Uint8Array(payload.encryptedSymmetricKey);

  let symmetricKey: Uint8Array;

  if (payload.encryptedKeyChain && payload.encryptedKeyChain.length > 0) {
    // Drive key hierarchy: resolve the chain from entry point to target
    const chain = payload.encryptedKeyChain.map((buf) => new Uint8Array(buf));
    symmetricKey = await resolveKeyChain(userId, encryptedKey, chain, payload.keyVersion);
  } else {
    // Docs flat model: direct key resolution
    symmetricKey = await resolveSymmetricKey(userId, encryptedKey, payload.keyVersion);
  }

  let decrypted: Uint8Array;

  try {
    decrypted = await decryptContent(encryptedContent, symmetricKey);
  } catch (err) {
    if (err instanceof VaultError && err.code === VaultErrorCode.WRONG_SECRET_KEY) {
      throw new VaultError(VaultErrorCode.CONTENT_INTEGRITY_FAILED, 'The content failed its integrity check under its unwrapped key.');
    }

    throw err;
  }

  return { data: decrypted.buffer as ArrayBuffer };
}
