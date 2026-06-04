import { exportPublicKeyAsBase64, getEncryptionDB, keyPairToPassphrase, passphraseToKeyPair } from '@encryption/src/crypto';
import { BROADCAST_KEYS_CHANGED, STORE_KEY_PAIRS } from '@encryption/src/shared/constants';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { getStoredKeyPair, serialized } from '@encryption/src/vault/operations/key-management';

export async function handleExportBackup(userId: string): Promise<{ passphrase: string }> {
  const pair = await getStoredKeyPair(userId);

  if (!pair) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'No key pair found. Generate keys first.');
  }

  return { passphrase: keyPairToPassphrase({ publicKey: pair.publicKey, secretKey: pair.secretKey }) };
}

export async function handleImportBackup(
  userId: string,
  payload: { passphrase: string }
): Promise<{ publicKey: string; previousKeyExists: boolean }> {
  return serialized(async () => {
    const keyPair = passphraseToKeyPair(payload.passphrase);

    // Check if keys already exist before overwriting
    const existingPair = await getStoredKeyPair(userId);
    const previousKeyExists = !!existingPair;

    const db = await getEncryptionDB();

    // Store as a pair scoped by userId
    await db.put(STORE_KEY_PAIRS, { publicKey: keyPair.publicKey, secretKey: keyPair.secretKey }, userId);

    const publicKeyBase64 = exportPublicKeyAsBase64(keyPair.publicKey);

    // Notify other tabs/iframes that keys changed
    getVaultBroadcastChannel()?.postMessage({ type: BROADCAST_KEYS_CHANGED });

    return { publicKey: publicKeyBase64, previousKeyExists };
  });
}
