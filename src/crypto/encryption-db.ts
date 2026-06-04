import { type IDBPDatabase, openDB } from 'idb';

import { DB_NAME, DB_VERSION, STORE_KEY_PAIRS, STORE_KNOWN_PUBLIC_KEYS } from '@encryption/src/shared/constants';

let dbPromise: Promise<IDBPDatabase> | null = null;

/**
 * Opens (or reuses) the encryption IndexedDB with all required object stores.
 * Uses a singleton promise so the upgrade callback only runs once.
 *
 * Stores:
 * - keyPairs: the user's own key pairs (public + private together), keyed by an identifier
 * - knownPublicKeys: registry of other users' public keys, keyed by user ID
 */
export function getEncryptionDB(): Promise<IDBPDatabase> {
  if (!dbPromise) {
    dbPromise = openDB(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains(STORE_KEY_PAIRS)) {
          db.createObjectStore(STORE_KEY_PAIRS);
        }
        if (!db.objectStoreNames.contains(STORE_KNOWN_PUBLIC_KEYS)) {
          db.createObjectStore(STORE_KNOWN_PUBLIC_KEYS);
        }
      },
    });
  }

  return dbPromise;
}
