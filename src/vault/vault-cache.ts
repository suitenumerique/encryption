/**
 * Local persistence for the synchronized vault, in the vault iframe's own
 * IndexedDB. One row per userId holds the sealed items + manifest + revision
 * (all ciphertext), the VRK wrapped under the device key, and the
 * non-extractable device key itself. Because the VRK is only ever stored
 * wrapped and the device key can't be exported, a copied database is inert.
 */
import { getEncryptionDB } from '@encryption/src/crypto/encryption-db';
import type { SealedItem } from '@encryption/src/crypto/vault-manifest';
import { STORE_VAULT_CACHE } from '@encryption/src/shared/constants';

export interface VaultCacheEntry {
  deviceKey: CryptoKey; // non-extractable AES-GCM key, structured-cloned into IDB
  wrappedVrk: Uint8Array; // VRK sealed under deviceKey
  sealed: SealedItem[]; // last known sealed item set
  manifest: string | null;
  manifestSig: string | null;
  revision: number;
}

/**
 * In-memory staging for an onboarding vault that has been minted locally but not
 * yet registered on the server. A staged vault lives here instead of IndexedDB so
 * that:
 *   - `has-keys` (which reads persisted state only) stays false while onboarding
 *     is in progress, so a product never treats an un-registered user as ready;
 *   - abandoning onboarding (reload, tab close, cancel) leaves nothing on disk;
 *   - every other vault operation still reads it transparently via getVaultCache.
 * The onboarding commit flushes it to disk (commitStagedVault) only once the
 * server registration has succeeded.
 */
const stagedVaults = new Map<string, VaultCacheEntry>();

export function stageVaultCache(userId: string, entry: VaultCacheEntry): void {
  stagedVaults.set(userId, entry);
}

/**
 * Read the persisted (IndexedDB) entry only, ignoring any staged vault. `has-keys`
 * uses this so an in-progress, not-yet-registered onboarding never reports ready.
 */
export async function getPersistedVaultCache(userId: string): Promise<VaultCacheEntry | null> {
  const db = await getEncryptionDB();
  const entry = (await db.get(STORE_VAULT_CACHE, userId)) as VaultCacheEntry | undefined;

  return entry ?? null;
}

export async function getVaultCache(userId: string): Promise<VaultCacheEntry | null> {
  return stagedVaults.get(userId) ?? getPersistedVaultCache(userId);
}

export async function saveVaultCache(userId: string, entry: VaultCacheEntry): Promise<void> {
  // While a vault is staged, its updates (reversioning before bootstrap, the
  // post-bootstrap sync) stay in memory too, so nothing lands on disk until the
  // commit flushes it.
  if (stagedVaults.has(userId)) {
    stagedVaults.set(userId, entry);

    return;
  }

  const db = await getEncryptionDB();
  await db.put(STORE_VAULT_CACHE, entry, userId);
}

/**
 * Promote a staged vault to persisted storage and drop the in-memory copy. Called
 * at the START of the onboarding commit, BEFORE the server sync, so the sync runs
 * against the real persisted vault (its read-modify-write and the post-bootstrap
 * revision land on disk like any normal sync). No-op when nothing is staged.
 */
export async function commitStagedVault(userId: string): Promise<void> {
  const staged = stagedVaults.get(userId);

  if (!staged) return;

  const db = await getEncryptionDB();
  await db.put(STORE_VAULT_CACHE, staged, userId);
  stagedVaults.delete(userId);
}

/**
 * Undo a commit when the onboarding server registration failed: move the persisted
 * vault back into the in-memory staging area and remove it from disk. `has-keys`
 * returns to false (the user is not registered), while the vault stays available
 * in memory so a retry can re-commit it without re-deriving keys or the phrase.
 * No-op when there is no persisted entry.
 */
export async function uncommitStagedVault(userId: string): Promise<void> {
  const db = await getEncryptionDB();
  const entry = (await db.get(STORE_VAULT_CACHE, userId)) as VaultCacheEntry | undefined;

  if (!entry) return;

  stagedVaults.set(userId, entry);
  await db.delete(STORE_VAULT_CACHE, userId);
}

export async function clearVaultCache(userId: string): Promise<void> {
  stagedVaults.delete(userId);

  const db = await getEncryptionDB();
  await db.delete(STORE_VAULT_CACHE, userId);
}

/**
 * Serialize a read-modify-write of the single cache row across every same-origin
 * vault context (each product tab embeds its own vault iframe, all sharing this
 * IndexedDB). Without this, two writers that both read the row before either
 * saves silently lose one write, e.g. a TOFU decision clobbered by a concurrent
 * sync. Web Locks is the same cross-tab mutex the UI already uses for token
 * refresh; it degrades to a plain call where the API is unavailable (tests).
 */
export async function withVaultCacheLock<T>(userId: string, fn: () => Promise<T>): Promise<T> {
  if (typeof navigator !== 'undefined' && navigator.locks) {
    return navigator.locks.request(`vault-cache:${userId}`, fn);
  }

  return fn();
}
