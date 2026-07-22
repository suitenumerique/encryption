import { tmpdir } from 'node:os';
import path from 'node:path';

// Where the jest global setup writes a ready-to-use Postgres data directory
// (schema applied, no rows), for each suite to restore into its own instance.
// A fixed path, rewritten on every run, keeps it readable from worker processes
// without env plumbing.
export const TEST_DATABASE_SNAPSHOT_PATH = path.join(tmpdir(), 'encryption-test-database.tar');
