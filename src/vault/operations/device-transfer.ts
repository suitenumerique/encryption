import { base64ToUint8, decryptContent, encryptContent, exportPublicKeyAsBase64, generateSymmetricKey, uint8ToBase64 } from '@encryption/src/crypto';
import { keyPairToPassphrase, passphraseToKeyPair } from '@encryption/src/crypto/encryption-backup';
import { getEncryptionDB } from '@encryption/src/crypto/encryption-db';
import { detectMnemonicLanguage, keyToMnemonic, mnemonicToKey } from '@encryption/src/crypto/mnemonic';
import { BROADCAST_KEYS_CHANGED, STORE_KEY_PAIRS, STORE_KNOWN_PUBLIC_KEYS } from '@encryption/src/shared/constants';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { getStoredKeyPair, serialized } from '@encryption/src/vault/operations/key-management';

/**
 * Prepare encrypted payload for device transfer (called on the OLD device).
 *
 * 1. Generates a temporary symmetric key (XChaCha20-Poly1305)
 * 2. Serializes: key pair (as passphrase JSON), known public keys registry
 * 3. Encrypts everything with the temporary key
 * 4. Returns:
 *    - encryptedPayload (base64) → sent to the server
 *    - transferPassphrase (24 French words) → displayed to the user, NEVER sent to the server
 */
export async function handlePrepareTransferExport(
  userId: string,
  options?: { language?: 'french' | 'english' }
): Promise<{ encryptedPayload: string; transferPassphrase: string }> {
  const pair = await getStoredKeyPair(userId);

  if (!pair) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'No key pair found. Cannot export.');
  }

  // Serialize the key pair as a passphrase string (base64url-encoded JSON of raw key bytes)
  const keyPairPassphrase = keyPairToPassphrase({ publicKey: pair.publicKey, secretKey: pair.secretKey });

  // Export known public keys registry for this user
  const db = await getEncryptionDB();
  const knownKeysStore = db.transaction(STORE_KNOWN_PUBLIC_KEYS, 'readonly').objectStore(STORE_KNOWN_PUBLIC_KEYS);
  const allKnownKeys: Record<string, unknown> = {};

  let cursor = await knownKeysStore.openCursor();

  while (cursor) {
    const key = String(cursor.key);
    const prefix = `${userId}:`;

    // Only export this user's known fingerprints
    if (key.startsWith(prefix)) {
      allKnownKeys[key.slice(prefix.length)] = cursor.value;
    }

    cursor = await cursor.continue();
  }

  // Bundle everything
  const payload = JSON.stringify({
    keyPairPassphrase,
    knownPublicKeys: allKnownKeys,
  });

  // Generate temporary symmetric key
  const transferKey = await generateSymmetricKey();

  // Encrypt the payload with the temporary key
  const payloadBytes = new TextEncoder().encode(payload);
  const encrypted = await encryptContent(payloadBytes, transferKey);

  // Export the transfer key as a mnemonic passphrase in the user's language
  const transferPassphrase = keyToMnemonic(transferKey, options?.language);

  return {
    encryptedPayload: uint8ToBase64(encrypted),
    transferPassphrase,
  };
}

/**
 * Import key material from a device transfer (called on the NEW device).
 *
 * 1. Converts the mnemonic passphrase back to the symmetric key
 * 2. Decrypts the payload
 * 3. Restores key pair and known public keys into IndexedDB
 */
export async function handleClaimTransferImport(
  userId: string,
  payload: { encryptedPayload: string; transferPassphrase: string }
): Promise<{ publicKey: string; previousKeyExists: boolean }> {
  return serialized(async () => {
    // Convert mnemonic back to symmetric key bytes
    const transferKey = mnemonicToKey(payload.transferPassphrase);

    // Detect the mnemonic language for informational logging
    const detectedLang = detectMnemonicLanguage(payload.transferPassphrase);

    if (detectedLang) {
      console.info(`Device transfer mnemonic detected as: ${detectedLang}`);
    }

    // Decrypt the payload
    const encrypted = base64ToUint8(payload.encryptedPayload);
    const decrypted = await decryptContent(encrypted, transferKey);

    const data = JSON.parse(new TextDecoder().decode(decrypted)) as {
      keyPairPassphrase: string;
      knownPublicKeys: Record<string, unknown>;
    };

    // Restore the key pair from its passphrase serialization
    const keyPair = passphraseToKeyPair(data.keyPairPassphrase);

    // Check if keys already exist before overwriting
    const existingPair = await getStoredKeyPair(userId);
    const previousKeyExists = !!existingPair;

    // Store in IndexedDB scoped by userId
    const db = await getEncryptionDB();

    await db.put(STORE_KEY_PAIRS, { publicKey: keyPair.publicKey, secretKey: keyPair.secretKey }, userId);

    // Restore known public keys, scoped by this userId
    const tx = db.transaction(STORE_KNOWN_PUBLIC_KEYS, 'readwrite');

    for (const [remoteKey, keyData] of Object.entries(data.knownPublicKeys)) {
      await tx.objectStore(STORE_KNOWN_PUBLIC_KEYS).put(keyData, `${userId}:${remoteKey}`);
    }

    await tx.done;

    // Notify other tabs/iframes that keys changed
    getVaultBroadcastChannel()?.postMessage({ type: BROADCAST_KEYS_CHANGED });

    // Return the public key as base64
    return { publicKey: exportPublicKeyAsBase64(keyPair.publicKey), previousKeyExists };
  });
}
