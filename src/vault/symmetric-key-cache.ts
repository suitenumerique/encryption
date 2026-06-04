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
 * - Keyed by: `${userId}:${encryptedKeyHash}` where hash is a simple fast hash
 * - Session-scoped: cleared on page reload (vault iframe reload)
 * - Size-limited: max 50 entries with LRU eviction
 */

const MAX_CACHE_SIZE = 50;

interface CacheEntry {
  symmetricKey: Uint8Array;
  lastUsed: number;
}

const cache = new Map<string, CacheEntry>();

/** Fast hash for cache key — NOT cryptographic, just for deduplication */
function fastHash(data: Uint8Array): string {
  let hash = 0;

  for (let i = 0; i < data.length; i++) {
    hash = ((hash << 5) - hash + data[i]) | 0;
  }

  return hash.toString(36);
}

function cacheKey(userId: string, encryptedKey: Uint8Array): string {
  return `${userId}:${fastHash(encryptedKey)}`;
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
