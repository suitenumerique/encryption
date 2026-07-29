import { decryptContent, decryptSymmetricKeyForUser } from '@encryption/src/crypto';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { type KeyVersionSelector, getStoredKeyPair } from '@encryption/src/vault/operations/key-management';
import { getCachedSymmetricKey, setCachedSymmetricKey } from '@encryption/src/vault/symmetric-key-cache';

export type { KeyVersionSelector };

/**
 * Resolve the symmetric key from an encrypted copy, unwrapping it with the
 * caller's encryption key selected by `version` (an exact retained version for
 * the read path, or `'active'` for the write paths — see {@link KeyVersionSelector}).
 * We select exactly that key and never try-all: the wrapped blob carries no
 * key-version tag, so guessing would only mask a wrong stored version. A
 * per-session cache short-circuits repeated hybrid decapsulation for the same
 * document key (so a warm read skips the vault load entirely).
 */
export async function resolveSymmetricKey(userId: string, encryptedKey: Uint8Array, version: KeyVersionSelector): Promise<Uint8Array> {
  const cached = getCachedSymmetricKey(userId, encryptedKey);

  if (cached) {
    return cached;
  }

  const pair = await getStoredKeyPair(userId, version);

  if (!pair) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'No key pair found. Generate or restore keys first.');
  }

  const symmetricKey = await decryptSymmetricKeyForUser(pair.secretKey, encryptedKey);

  setCachedSymmetricKey(userId, encryptedKey, symmetricKey);

  return symmetricKey;
}

/**
 * Resolve a chain of wrapped symmetric keys, starting from the user's
 * entry-point key and unwrapping each subsequent key in the chain.
 *
 * Used by Drive's key hierarchy: each item's key is wrapped by its parent's key.
 * The chain represents the path from the user's access point down to the target item.
 *
 * All intermediate keys stay inside the vault — they never leave this iframe.
 *
 * @param userId - The current user's ID (for resolving the entry-point key)
 * @param encryptedSymmetricKey - The user's entry-point key (encrypted with their public key)
 * @param encryptedKeyChain - Ordered array of wrapped keys from entry point to target.
 *   Each key[i] is encrypted (wrapped) by the key resolved at step i-1.
 * @param version - Selects the encryption key that unwraps the ENTRY-point key
 *   (the chain links below are symmetric, so only the entry needs it): a stored
 *   version number (read path) or `'active'` (write paths).
 * @returns The final resolved symmetric key at the end of the chain
 */
export async function resolveKeyChain(
  userId: string,
  encryptedSymmetricKey: Uint8Array,
  encryptedKeyChain: Uint8Array[],
  version: KeyVersionSelector
): Promise<Uint8Array> {
  // Step 1: Decrypt the entry-point key using the user's private key of `version`
  let currentKey = await resolveSymmetricKey(userId, encryptedSymmetricKey, version);

  // Step 2: Unwrap each subsequent key in the chain
  for (const wrappedKey of encryptedKeyChain) {
    currentKey = await decryptContent(wrappedKey, currentKey);
  }

  return currentKey;
}
