import { BROADCAST_KEYS_DESTROYED } from '@encryption/src/shared/constants';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { serialized } from '@encryption/src/vault/operations/key-management';
import { clearSymmetricKeyCache } from '@encryption/src/vault/symmetric-key-cache';
import { clearVaultCache, withVaultCacheLock } from '@encryption/src/vault/vault-cache';

export async function handleDestroyKeys(userId: string): Promise<{ destroyed: boolean }> {
  return serialized(async () => {
    // Drop the synchronized-vault cache (sealed items, wrapped VRK, device key).
    // This is the only local store; key material lives sealed inside it.
    //
    // Take the cross-tab cache lock: `serialized()` only orders operations
    // within THIS iframe, but a sync running in another tab holds
    // `withVaultCacheLock` while it reads-modifies-writes the same entry. Without
    // the lock here, that sync could complete after we clear and rewrite the full
    // entry (device key, wrapped VRK, sealed items) back into IndexedDB, leaving
    // the device enrolled after the user was told the keys were destroyed.
    await withVaultCacheLock(userId, () => clearVaultCache(userId));

    // Drop decrypted-key cache too, so nothing can decrypt after keys are gone.
    clearSymmetricKeyCache();

    // Notify other tabs/iframes that keys were destroyed
    getVaultBroadcastChannel()?.postMessage({ type: BROADCAST_KEYS_DESTROYED });

    return { destroyed: true };
  });
}
