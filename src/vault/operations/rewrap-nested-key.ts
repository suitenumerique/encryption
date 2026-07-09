import { decryptContent, encryptContent } from '@encryption/src/crypto';
import { resolveKeyChain, resolveSymmetricKey } from '@encryption/src/vault/operations/symmetric-key-utils';

/**
 * Re-wrap a nested symmetric key from one parent chain onto another.
 *
 * Used when an encrypted resource (typically a file) is MOVED inside an
 * encrypted subtree: the file's content stays encrypted with the same
 * K_file, but K_file's wrapping needs to follow the file's new parent.
 *
 * Flow:
 *   1. Resolve the OLD chain (entry → … → old parent) to get K_oldParent.
 *   2. Decrypt `oldEncryptedKey` (K_file wrapped under K_oldParent) → K_file.
 *   3. Resolve the NEW chain (entry → … → new parent) to get K_newParent.
 *   4. Encrypt K_file with K_newParent → newEncryptedKey.
 *
 * The user's entry-point key (`encryptedSymmetricKey` — root key wrapped
 * under the user's pubkey) is shared between both chains: this operation
 * is for moves within a single encrypted root. Cross-root moves require
 * different access plumbing and are out of scope here.
 *
 * `oldEncryptedKeyChain` / `newEncryptedKeyChain` are optional — empty /
 * undefined means "the parent IS the encryption root" (the file lives
 * directly under root in the old or new position).
 */
export async function handleRewrapNestedKey(
  userId: string,
  payload: {
    encryptedSymmetricKey: ArrayBuffer;
    oldEncryptedKey: ArrayBuffer;
    oldEncryptedKeyChain?: ArrayBuffer[];
    newEncryptedKeyChain?: ArrayBuffer[];
  }
): Promise<{ newEncryptedKey: ArrayBuffer }> {
  const entryKey = new Uint8Array(payload.encryptedSymmetricKey);
  const oldWrappedKey = new Uint8Array(payload.oldEncryptedKey);

  const resolveChainOrEntry = async (chain?: ArrayBuffer[]): Promise<Uint8Array> =>
    chain && chain.length > 0
      ? resolveKeyChain(
          userId,
          entryKey,
          chain.map((buf) => new Uint8Array(buf))
        )
      : resolveSymmetricKey(userId, entryKey);

  const oldParentKey = await resolveChainOrEntry(payload.oldEncryptedKeyChain);
  const fileKey = await decryptContent(oldWrappedKey, oldParentKey);

  const newParentKey = await resolveChainOrEntry(payload.newEncryptedKeyChain);
  const newWrappedKey = await encryptContent(fileKey, newParentKey);

  return { newEncryptedKey: newWrappedKey.buffer as ArrayBuffer };
}
