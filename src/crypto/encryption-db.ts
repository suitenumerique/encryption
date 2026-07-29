import { type IDBPDatabase, openDB } from 'idb';

import { DB_NAME, STORE_USER_ALIAS, STORE_VAULT_CACHE } from '@encryption/src/shared/constants';

let dbPromise: Promise<IDBPDatabase> | null = null;

/**
 * Ordered schema migrations, one entry per DB version (index 0 = v1). Each entry
 * applies exactly the stores/indexes introduced at that version.
 *
 * APPEND-ONLY, and this is the whole point: `DB_VERSION` below is DERIVED from the
 * length, so adding a store here ALWAYS bumps the version. You cannot forget the
 * bump, which is the class of bug this guards against: IndexedDB only runs
 * `upgrade` on a version INCREASE, so a store added at the same version is never
 * created for a database an earlier build already opened, and every transaction on
 * it throws "object store not found".
 *
 * Each step also guards its own `createObjectStore` (`contains` check) so a
 * database in any drifted state converges instead of throwing "store already
 * exists". Never rewrite a past entry once shipped; only append.
 *
 * Exported so the migration test can build a database "as of version N" from the
 * real steps and assert every upgrade path preserves data and reaches the current schema.
 */
export const MIGRATIONS: ReadonlyArray<(db: IDBPDatabase) => void> = [
  // v1 — the synchronized vault's local cache.
  (db) => {
    if (!db.objectStoreNames.contains(STORE_VAULT_CACHE)) db.createObjectStore(STORE_VAULT_CACHE);
  },
  // v2 — the `sub -> internal user id` alias map.
  (db) => {
    if (!db.objectStoreNames.contains(STORE_USER_ALIAS)) db.createObjectStore(STORE_USER_ALIAS);
  },
];

/** Current schema version = number of migrations. Do not hand-edit; add a migration. */
export const DB_VERSION = MIGRATIONS.length;

/**
 * Opens (or reuses) the encryption IndexedDB. Uses a singleton promise so the
 * upgrade callback only runs once. The only store is the synchronized vault
 * cache; key material and the known-key registry live inside the sealed vault,
 * not in plaintext stores of their own.
 */
export function getEncryptionDB(): Promise<IDBPDatabase> {
  if (!dbPromise) {
    dbPromise = openDB(DB_NAME, DB_VERSION, {
      upgrade(db, oldVersion) {
        // Apply every migration this database has not run yet, in order.
        // `oldVersion` is 0 for a brand-new database, or the stored version for an
        // existing one, so each migration runs exactly once per browser.
        for (let v = oldVersion; v < MIGRATIONS.length; v++) {
          MIGRATIONS[v](db);
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
