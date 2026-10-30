/**
 * Local persistence for the synchronized vault, in the vault iframe's own
 * IndexedDB. One row per userId holds the sealed items + manifest + revision
 * (all ciphertext), the VRK wrapped under the device key, and the
 * non-extractable device key itself. Because the VRK is only ever stored
 * wrapped and the device key can't be exported, a copied database is inert.
 */
import { getEncryptionDB } from '@encryption/src/crypto/encryption-db';
import type { SealedItem } from '@encryption/src/crypto/vault-manifest';
import { STORE_DEVICE_ACTIVITY, STORE_VAULT_CACHE } from '@encryption/src/shared/constants';
import { type DeviceActivity, expireIfInactive, forgetRecordedUse, isPastInactivityDelay, usedAt } from '@encryption/src/vault/device-activity';

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
 * Every read of the disk copy goes through here, so a vault left unused past the
 * inactivity delay is forgotten before anything can unlock it.
 */
export async function getPersistedVaultCache(userId: string): Promise<VaultCacheEntry | null> {
  const db = await getEncryptionDB();
  const tx = db.transaction([STORE_VAULT_CACHE, STORE_DEVICE_ACTIVITY], 'readonly');
  const [entry, activity] = (await Promise.all([
    tx.objectStore(STORE_VAULT_CACHE).get(userId),
    tx.objectStore(STORE_DEVICE_ACTIVITY).get(userId),
    tx.done,
  ])) as [VaultCacheEntry | undefined, DeviceActivity | undefined, void];

  // The expiry re-checks in its own write transaction, so a use recorded by
  // another tab in between keeps the vault.
  if (entry && isPastInactivityDelay(activity) && (await expireIfInactive(userId))) return null;

  return entry ?? null;
}

// Writing the vault to disk (enrollment, restore, pairing, any mutation) is a use,
// in the same transaction so the cache row never lands without its date.
async function putPersistedVaultCache(userId: string, entry: VaultCacheEntry): Promise<void> {
  const db = await getEncryptionDB();
  const tx = db.transaction([STORE_VAULT_CACHE, STORE_DEVICE_ACTIVITY], 'readwrite');
  await Promise.all([tx.objectStore(STORE_VAULT_CACHE).put(entry, userId), tx.objectStore(STORE_DEVICE_ACTIVITY).put(usedAt(), userId), tx.done]);
}

async function deletePersistedVaultCache(userId: string): Promise<void> {
  const db = await getEncryptionDB();
  const tx = db.transaction([STORE_VAULT_CACHE, STORE_DEVICE_ACTIVITY], 'readwrite');
  await Promise.all([tx.objectStore(STORE_VAULT_CACHE).delete(userId), tx.objectStore(STORE_DEVICE_ACTIVITY).delete(userId), tx.done]);
  forgetRecordedUse(userId);
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

  await putPersistedVaultCache(userId, entry);
}

/**
 * Promote a staged vault to persisted storage and drop the in-memory copy. Called
 * at the START of the onboarding commit, BEFORE the server sync, so the sync runs
 * against the real persisted vault (its read-modify-write and the post-bootstrap
 * revision land on disk like any normal sync). No-op when nothing is staged.
 */
export async function commitStagedVault(userId: string): Promise<boolean> {
  const staged = stagedVaults.get(userId);

  if (!staged) return false;

  await putPersistedVaultCache(userId, staged);
  stagedVaults.delete(userId);

  return true;
}

/**
 * Undo a commit when the onboarding server registration failed: move the persisted
 * vault back into the in-memory staging area and remove it from disk. `has-keys`
 * returns to false (the user is not registered), while the vault stays available
 * in memory so a retry can re-commit it without re-deriving keys or the phrase.
 * No-op when there is no persisted entry.
 */
export async function uncommitStagedVault(userId: string): Promise<boolean> {
  const db = await getEncryptionDB();
  const entry = (await db.get(STORE_VAULT_CACHE, userId)) as VaultCacheEntry | undefined;

  if (!entry) return false;

  stagedVaults.set(userId, entry);
  await deletePersistedVaultCache(userId);

  return true;
}

export async function clearVaultCache(userId: string): Promise<void> {
  stagedVaults.delete(userId);
  await deletePersistedVaultCache(userId);
}

/**
 * Serialize a read-modify-write of the single cache row across every same-origin
 * vault context (each product tab embeds its own vault iframe, all sharing this
 * IndexedDB). Without this, two writers that both read the row before either
 * saves silently lose one write, e.g. a TOFU decision clobbered by a concurrent
 * sync. Web Locks is the browser's cross-tab mutex; it degrades to a plain call
 * where the API is unavailable (tests).
 */
export async function withVaultCacheLock<T>(userId: string, fn: () => Promise<T>): Promise<T> {
  if (typeof navigator !== 'undefined' && navigator.locks) {
    return navigator.locks.request(`vault-cache:${userId}`, fn);
  }

  return fn();
}
