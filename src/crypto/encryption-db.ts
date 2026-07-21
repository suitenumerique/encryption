import { type IDBPDatabase, openDB } from 'idb';

import { DB_NAME, DB_VERSION, STORE_USER_ALIAS, STORE_VAULT_CACHE } from '@encryption/src/shared/constants';

let dbPromise: Promise<IDBPDatabase> | null = null;

/**
 * Opens (or reuses) the encryption IndexedDB. Uses a singleton promise so the
 * upgrade callback only runs once. The only store is the synchronized vault
 * cache; key material and the known-key registry live inside the sealed vault,
 * not in plaintext stores of their own.
 */
export function getEncryptionDB(): Promise<IDBPDatabase> {
  if (!dbPromise) {
    dbPromise = openDB(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains(STORE_VAULT_CACHE)) {
          db.createObjectStore(STORE_VAULT_CACHE);
        }
        if (!db.objectStoreNames.contains(STORE_USER_ALIAS)) {
          db.createObjectStore(STORE_USER_ALIAS);
        }
      },
      // Browser abnormally killed the connection — reopen on next call.
      terminated() {
        dbPromise = null;
      },
    })
      .then((db) => {
        // A closed connection (versionchange from another tab, HMR reload, or
        // the browser reclaiming an idle handle) must not stay cached, or the
        // next transaction throws "The database connection is closing".
        db.addEventListener('close', () => {
          dbPromise = null;
        });

        return db;
      })
      .catch((err: unknown) => {
        dbPromise = null;
        throw err;
      });
  }

  return dbPromise;
}
