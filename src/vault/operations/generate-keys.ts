import { exportPublicKeyAsBase64, generateUserKeyPair, getEncryptionDB } from '@encryption/src/crypto';
import { BROADCAST_KEYS_CHANGED, STORE_KEY_PAIRS } from '@encryption/src/shared/constants';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { serialized } from '@encryption/src/vault/operations/key-management';

export async function handleGenerateKeys(userId: string): Promise<{ publicKey: string }> {
  return serialized(async () => {
    const keyPair = await generateUserKeyPair();
    const db = await getEncryptionDB();

    await db.put(STORE_KEY_PAIRS, { publicKey: keyPair.publicKey, secretKey: keyPair.secretKey }, userId);

    const publicKeyBase64 = exportPublicKeyAsBase64(keyPair.publicKey);

    // Notify other tabs/iframes that keys changed
    getVaultBroadcastChannel()?.postMessage({ type: BROADCAST_KEYS_CHANGED });

    return { publicKey: publicKeyBase64 };
  });
}
