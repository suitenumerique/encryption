import { serialized } from '@encryption/src/vault/operations/key-management';
import { commitStagedVault, uncommitStagedVault, withVaultCacheLock } from '@encryption/src/vault/vault-cache';

/**
 * Commit the staged (in-memory) onboarding vault to IndexedDB, making it durable
 * and visible to has-keys. Called at the START of the onboarding commit, before
 * the server sync, so the sync runs against the real persisted vault. A no-op when
 * nothing is staged (e.g. a non-onboarding generate).
 */
export async function handleCommitStagedVault(userId: string): Promise<{ committed: boolean }> {
  await serialized(() => withVaultCacheLock(userId, () => commitStagedVault(userId)));

  return { committed: true };
}

/**
 * Roll the just-committed onboarding vault back out of IndexedDB when the server
 * registration failed: it returns to in-memory staging so has-keys is false again
 * and a retry can re-commit it without re-deriving keys or the recovery phrase.
 */
export async function handleUncommitStagedVault(userId: string): Promise<{ uncommitted: boolean }> {
  await serialized(() => withVaultCacheLock(userId, () => uncommitStagedVault(userId)));

  return { uncommitted: true };
}
