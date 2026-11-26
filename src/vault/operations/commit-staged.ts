import { BROADCAST_KEYS_CHANGED } from '@encryption/src/shared/constants';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { serialized } from '@encryption/src/vault/operations/key-management';
import { commitStagedVault, uncommitStagedVault, withVaultCacheLock } from '@encryption/src/vault/vault-cache';

/**
 * Commit the staged (in-memory) onboarding vault to IndexedDB, making it durable
 * and visible to has-keys. Called at the START of the onboarding commit, before
 * the server sync, so the sync runs against the real persisted vault. A no-op when
 * nothing is staged (e.g. a non-onboarding generate).
 */
export async function handleCommitStagedVault(userId: string): Promise<{ committed: boolean }> {
  // Other tabs learn of the new keys only now that has-keys can see them: told
  // earlier, a product asks, hears "no keys", and is never told again.
  if (await serialized(() => withVaultCacheLock(userId, () => commitStagedVault(userId)))) {
    getVaultBroadcastChannel()?.postMessage({ type: BROADCAST_KEYS_CHANGED });
  }

  return { committed: true };
}

/**
 * Roll the just-committed onboarding vault back out of IndexedDB when the server
 * registration failed: it returns to in-memory staging so has-keys is false again
 * and a retry can re-commit it without re-deriving keys or the recovery phrase.
 */
export async function handleUncommitStagedVault(userId: string): Promise<{ uncommitted: boolean }> {
  if (await serialized(() => withVaultCacheLock(userId, () => uncommitStagedVault(userId)))) {
    getVaultBroadcastChannel()?.postMessage({ type: BROADCAST_KEYS_CHANGED });
  }

  return { uncommitted: true };
}
