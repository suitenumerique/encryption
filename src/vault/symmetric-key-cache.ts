import { uint8ToBase64 } from '@encryption/src/crypto';

/**
 * Session-only cache for decrypted symmetric keys.
 *
 * When the vault receives an encrypted symmetric key (e.g. for WebSocket messages
 * or document save operations), it needs to decrypt it with the user's private key
 * before using it for content encryption/decryption. The decryption involves
 * hybrid decapsulation (X25519 + post-quantum slot) which is CPU-intensive.
 *
 * Since the same encrypted symmetric key is sent repeatedly for the same document
 * (every WebSocket message, every auto-save), caching the decrypted result avoids
 * redundant decapsulation operations.
 *
 * The cache is:
 * - In-memory only (lives in the vault iframe, never persisted)
 * - Keyed by: `${userId}:${base64(encryptedKey)}` — the FULL wrapped-key bytes,
 *   not a short hash. A non-cryptographic hash (previously a 32-bit rolling
 *   hash) is trivially collidable: a caller could craft a garbage wrapped-key
 *   blob that hashes to a cached entry's bucket and get another document's key
 *   returned without ever possessing that document's wrapped key. Keying by the
 *   lossless base64 of the exact bytes makes a hit require byte-for-byte
 *   equality, so a collision cannot return the wrong key.
 * - Session-scoped: cleared on page reload (vault iframe reload)
 * - Size-limited: max 50 entries with LRU eviction
 */

const MAX_CACHE_SIZE = 50;

interface CacheEntry {
  symmetricKey: Uint8Array;
  lastUsed: number;
}

const cache = new Map<string, CacheEntry>();

function cacheKey(userId: string, encryptedKey: Uint8Array): string {
  return `${userId}:${uint8ToBase64(encryptedKey)}`;
}

/**
 * Get a cached decrypted symmetric key, or null if not cached.
 */
export function getCachedSymmetricKey(userId: string, encryptedKey: Uint8Array): Uint8Array | null {
  const key = cacheKey(userId, encryptedKey);
  const entry = cache.get(key);

  if (entry) {
    entry.lastUsed = Date.now();

    return entry.symmetricKey;
  }

  return null;
}

/**
 * Drop every cached key. MUST be called whenever the active vault/keyring
 * changes (new identity, restore, reactivate, adopt, destroy, or another tab
 * changing the keys), because cache entries are keyed by userId — which is
 * STABLE across identity changes — so a stale entry from a previous vault would
 * otherwise let a document decrypt against a vault that can no longer unwrap it.
 */
export function clearSymmetricKeyCache(): void {
  cache.clear();
}

/**
 * Store a decrypted symmetric key in the cache.
 */
export function setCachedSymmetricKey(userId: string, encryptedKey: Uint8Array, symmetricKey: Uint8Array): void {
  const key = cacheKey(userId, encryptedKey);

  // Evict LRU entries if cache is full
  if (cache.size >= MAX_CACHE_SIZE && !cache.has(key)) {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;

    for (const [k, v] of cache) {
      if (v.lastUsed < oldestTime) {
        oldestTime = v.lastUsed;
        oldestKey = k;
      }
    }

    if (oldestKey) {
      cache.delete(oldestKey);
    }
  }

  cache.set(key, { symmetricKey, lastUsed: Date.now() });
}
