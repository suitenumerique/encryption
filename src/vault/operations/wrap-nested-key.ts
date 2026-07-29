import { encryptContent } from '@encryption/src/crypto';
import { resolveKeyChain, resolveSymmetricKey } from '@encryption/src/vault/operations/symmetric-key-utils';

/**
 * Wrap an existing symmetric key under a parent chain.
 *
 * Symmetric reverse of `handleRewrapNestedKey`: that one converts a
 * chain-anchored wrap to another chain-anchored wrap. This one converts
 * a per-user-anchored wrap (the value stored in an access row's
 * `encrypted_item_symmetric_key_for_user`) into a chain-anchored wrap.
 *
 * Used when a self-rooted encrypted resource (typically a file that's
 * its own encryption root, with per-user wraps) is moved INTO an
 * encrypted subtree. After the move the resource shouldn't be its own
 * root anymore — its `K_item` belongs under the destination parent's
 * chain. The caller persists the returned `newEncryptedKey` on the
 * resource's row and clears the per-user wraps on access rows.
 *
 * Flow:
 *   1. Decrypt `userEncryptedKey` (K_item wrapped under the user's
 *      pubkey) using the user's private key → K_item.
 *   2. Resolve the NEW chain (entry → … → new parent) → K_newParent.
 *      An empty chain means "the new parent IS the encryption root".
 *   3. Encrypt K_item with K_newParent → newEncryptedKey.
 *
 * The new entry key (`newEntryEncryptedSymmetricKey`) is the user's
 * wrap of the destination tree's root — the same value `getKeyChain`
 * returns as `encrypted_key_for_user` for any item under that tree.
 */
export async function handleWrapNestedKey(
  userId: string,
  payload: {
    userEncryptedKey: ArrayBuffer;
    newEntryEncryptedSymmetricKey: ArrayBuffer;
    newEncryptedKeyChain?: ArrayBuffer[];
  }
): Promise<{ newEncryptedKey: ArrayBuffer }> {
  // (1) Recover K_item from the per-user wrap.
  const fileKey = await resolveSymmetricKey(userId, new Uint8Array(payload.userEncryptedKey), 'active');

  // (2) Resolve the destination chain to its terminal key. Empty
  //     chain means the user's entry already lands on the destination
  //     parent (i.e. the parent is the destination tree's root).
  const newEntryKey = new Uint8Array(payload.newEntryEncryptedSymmetricKey);
  const newParentKey =
    payload.newEncryptedKeyChain && payload.newEncryptedKeyChain.length > 0
      ? await resolveKeyChain(
          userId,
          newEntryKey,
          payload.newEncryptedKeyChain.map((buf) => new Uint8Array(buf)),
          'active'
        )
      : await resolveSymmetricKey(userId, newEntryKey, 'active');

  // (3) Wrap K_item under K_newParent.
  const newEncryptedKey = await encryptContent(fileKey, newParentKey);

  return { newEncryptedKey: newEncryptedKey.buffer as ArrayBuffer };
}
