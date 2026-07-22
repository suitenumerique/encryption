import { PGlite } from '@electric-sql/pglite';
import { readFileSync } from 'node:fs';
import { PrismaPGlite } from 'pglite-prisma-adapter';

import { PrismaClient } from '@encryption/src/generated/prisma/client';
import { TEST_DATABASE_SNAPSHOT_PATH } from '@encryption/src/prisma/testing-schema';

/**
 * Real Postgres for the unit tier, in-process.
 *
 * PGlite is Postgres 17 compiled to WebAssembly, so tests exercise the actual
 * engine (enums, cascades, unique constraints, transactions, `@db.Uuid`) with
 * no Docker and no daemon. Each SUITE restores the schema-only snapshot built
 * by the global setup (~120 ms) and empties its tables between tests (~7 ms),
 * so files stay independent and jest keeps scheduling them across workers with
 * no coordination, which is what makes `--maxWorkers` still worth raising in CI.
 *
 * Sharing one engine per worker instead was measured and rejected: the engine
 * would then live in the worker realm while the driver adapter lives in the
 * per-file sandbox, and the adapter stops recognising the errors it must map
 * (a unique violation no longer surfaces as P2002), which silently changes the
 * behaviour under test.
 *
 * The one thing PGlite cannot reproduce is CONTENDED concurrency. Behind the
 * API there is a single Postgres backend (`pg_backend_pid()` is constant), so a
 * second session cannot exist: a competing transaction is queued rather than
 * run, and session-level advisory locks are shared instead of exclusive. Tests
 * may therefore assert that a lock is taken and released (`pg_locks` works),
 * never that a competitor is excluded. Anything that needs two live sessions
 * (advisory-lock mutual exclusion, a Serializable 40001 retry, a unique-constraint
 * race) stays mocked, with a comment at the mock saying so.
 */
let db: PGlite | null = null;
let client: PrismaClient | null = null;
let truncateStatement: string | null = null;

function requireClient(): PrismaClient {
  if (!client) {
    throw new Error('No test database: call useTestDatabase() at the top level of the suite');
  }

  return client;
}

/**
 * The client itself, for the rare test that must spy on it (`jest.spyOn` needs
 * the real object, the proxy below hands back bound copies). Use `testPrisma`
 * everywhere else.
 */
export function testPrismaClient(): PrismaClient {
  return requireClient();
}

// Stands in for the `prisma` singleton so a suite can mock the client module
// before the database exists (jest.mock factories run at import time, the
// database is restored in beforeAll).
export const testPrisma = new Proxy({} as PrismaClient, {
  get(_target, property) {
    const value = Reflect.get(requireClient(), property);

    return typeof value === 'function' ? value.bind(client) : value;
  },
});

async function start(): Promise<void> {
  db = await PGlite.create({ loadDataDir: new Blob([readFileSync(TEST_DATABASE_SNAPSHOT_PATH)]) });
  client = new PrismaClient({ adapter: new PrismaPGlite(db) } as never);

  const tables = await client.$queryRaw<{ tablename: string }[]>`SELECT tablename FROM pg_tables WHERE schemaname = 'public'`;
  truncateStatement = `TRUNCATE TABLE ${tables.map((row) => `"public"."${row.tablename}"`).join(', ')} CASCADE`;
}

async function stop(): Promise<void> {
  await client?.$disconnect();
  await db?.close();
  db = null;
  client = null;
  truncateStatement = null;
}

export async function emptyTestDatabase(): Promise<void> {
  if (truncateStatement) {
    await db!.exec(truncateStatement);
  }
}

/** Restores one database for the suite and empties it between tests. */
export function useTestDatabase(): void {
  beforeAll(start, 60000);
  afterEach(emptyTestDatabase);
  afterAll(stop);
}
