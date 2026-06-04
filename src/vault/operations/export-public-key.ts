import { exportPublicKeyAsBase64, getEncryptionDB, keyPairToPassphrase, passphraseToKeyPair } from '@encryption/src/crypto';
import { BROADCAST_KEYS_CHANGED, STORE_KEY_PAIRS } from '@encryption/src/shared/constants';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { getStoredKeyBundle, serialized } from '@encryption/src/vault/operations/key-management';

export async function handleExportBackup(userId: string): Promise<{ passphrase: string }> {
  // getStoredKeyBundle throws MISSING_KEYS if there is no pair (or a legacy
  // pair without an identity key), so the backup always contains both keys.
  const bundle = await getStoredKeyBundle(userId);

  return { passphrase: keyPairToPassphrase(bundle) };
}

export async function handleImportBackup(
  userId: string,
  payload: { passphrase: string }
): Promise<{ publicKey: string; signaturePublicKey: string; previousKeyExists: boolean }> {
  return serialized(async () => {
    const bundle = passphraseToKeyPair(payload.passphrase);

    const db = await getEncryptionDB();

    // Check if keys already exist before overwriting
    const existingPair = await db.get(STORE_KEY_PAIRS, userId);
    const previousKeyExists = !!existingPair;

    // Store both key pairs together, scoped by userId.
    await db.put(
      STORE_KEY_PAIRS,
      {
        publicKey: bundle.encryption.publicKey,
        secretKey: bundle.encryption.secretKey,
        signaturePublicKey: bundle.signature.publicKey,
        signatureSecretKey: bundle.signature.secretKey,
      },
      userId
    );

    // Notify other tabs/iframes that keys changed
    getVaultBroadcastChannel()?.postMessage({ type: BROADCAST_KEYS_CHANGED });

    return {
      publicKey: exportPublicKeyAsBase64(bundle.encryption.publicKey),
      signaturePublicKey: exportPublicKeyAsBase64(bundle.signature.publicKey),
      previousKeyExists,
    };
  });
}
