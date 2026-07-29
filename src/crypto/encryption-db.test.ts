import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { type IDBPDatabase, openDB } from 'idb';

import { DB_NAME, STORE_USER_ALIAS, STORE_VAULT_CACHE } from '@encryption/src/shared/constants';
import { MIGRATIONS } from '@encryption/src/crypto/encryption-db';

// Each test starts from an empty IndexedDB and a fresh module, so
// getEncryptionDB's cached connection promise never leaks a handle (or a stale
// schema) across cases.
beforeEach(() => {
  globalThis.indexedDB = new IDBFactory();
  jest.resetModules();
});

function importDb() {
  return import('@encryption/src/crypto/encryption-db');
}

/** Sorted object-store names, via the DOMStringList API (portable across fakes). */
function storeNames(db: IDBPDatabase): string[] {
  const out: string[] = [];
  for (let i = 0; i < db.objectStoreNames.length; i++) {
    const name = db.objectStoreNames.item(i);
    if (name !== null) out.push(name);
  }
  return out.sort();
}

/** A database built "as of version N" from the REAL migration steps. */
function openAtVersion(version: number): Promise<IDBPDatabase> {
  return openDB(DB_NAME, version, {
    upgrade(db, oldVersion) {
      for (let v = oldVersion; v < version; v++) MIGRATIONS[v](db);
    },
  });
}

describe('encryption IndexedDB schema', () => {
  // Explicit schema check: the one place that NAMES the expected stores, so a
  // migration that fails to create what it should is caught (not just "matches
  // itself"). Add one assertion here when you introduce a store.
  it('opens a brand-new database at DB_VERSION with every current object store', async () => {
    const { getEncryptionDB, DB_VERSION } = await importDb();

    const db = await getEncryptionDB();

    expect(db.version).toBe(DB_VERSION);
    expect(db.objectStoreNames.contains(STORE_VAULT_CACHE)).toBe(true);
    expect(db.objectStoreNames.contains(STORE_USER_ALIAS)).toBe(true);

    db.close();
  });

  // The store set a brand-new install ends with — the target every upgrade must
  // reach. Computed from the real code in an isolated factory.
  let targetSchema: string[];

  beforeAll(async () => {
    globalThis.indexedDB = new IDBFactory();
    jest.resetModules();
    const { getEncryptionDB } = await importDb();
    const db = await getEncryptionDB();
    targetSchema = storeNames(db);
    db.close();
  });

  // Data-driven, so ANY future version is covered with no edit here: for every
  // prior version, seed a database at that version from the real migrations, put a
  // probe row in each store it has, then open through the real code and assert the
  // upgrade preserved every probe AND converged to the exact fresh-install schema.
  // This is the regression for the Safari failure (a store added without an
  // effective migration would leave the upgraded schema short of `targetSchema`).
  const priorVersions = Array.from({ length: Math.max(0, MIGRATIONS.length - 1) }, (_, i) => i + 1);

  describe.each(priorVersions)('a database created at version %i', (from) => {
    it('upgrades to the current schema and preserves its data', async () => {
      const legacy = await openAtVersion(from);
      const seededStores = storeNames(legacy);
      for (const name of seededStores) {
        await legacy.put(name, { seededAt: from, store: name }, 'probe');
      }
      legacy.close();

      const { getEncryptionDB, DB_VERSION } = await importDb();
      const db = await getEncryptionDB();

      expect(db.version).toBe(DB_VERSION);
      expect(storeNames(db)).toEqual(targetSchema);
      for (const name of seededStores) {
        expect(await db.get(name, 'probe')).toEqual({ seededAt: from, store: name });
      }

      db.close();
    });
  });
});
