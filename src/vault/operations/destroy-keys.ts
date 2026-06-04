import { getEncryptionDB } from '@encryption/src/crypto';
import { BROADCAST_KEYS_DESTROYED, STORE_KEY_PAIRS, STORE_KNOWN_PUBLIC_KEYS } from '@encryption/src/shared/constants';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { serialized } from '@encryption/src/vault/operations/key-management';

export async function handleDestroyKeys(userId: string): Promise<{ destroyed: boolean }> {
  return serialized(async () => {
    const db = await getEncryptionDB();

    // Delete this user's key pair
    await db.delete(STORE_KEY_PAIRS, userId);

    // Delete this user's known fingerprints registry
    const tx = db.transaction(STORE_KNOWN_PUBLIC_KEYS, 'readwrite');
    const store = tx.objectStore(STORE_KNOWN_PUBLIC_KEYS);
    let cursor = await store.openCursor();

    while (cursor) {
      const key = String(cursor.key);

      if (key.startsWith(`${userId}:`)) {
        await cursor.delete();
      }

      cursor = await cursor.continue();
    }

    await tx.done;

    // Notify other tabs/iframes that keys were destroyed
    getVaultBroadcastChannel()?.postMessage({ type: BROADCAST_KEYS_DESTROYED });

    return { destroyed: true };
  });
}
