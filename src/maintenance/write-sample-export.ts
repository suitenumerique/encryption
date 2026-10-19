/**
 * Writes `src/maintenance/sample-export/`: the sample export (see testing.ts) as a
 * folder on disk, encrypted for the development maintenance phrase, the way a
 * product team hands one over. Committed, so anyone can open the maintenance tool
 * on it, and frozen, so `sample-export.test.ts` proves an export made once keeps
 * decrypting. Rewritten only when the export format changes on purpose:
 *
 *   npm run maintenance:sample-export
 */
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { importMaintenancePublicKey } from '@encryption/src/crypto/maintenance-escrow';
import { DEV_MAINTENANCE_PUBLIC_KEY } from '@encryption/src/maintenance/dev-maintenance-key';
import { buildSampleExport } from '@encryption/src/maintenance/testing';

const root = resolve(import.meta.dirname, 'sample-export');

rmSync(root, { recursive: true, force: true });

for (const [path, data] of Object.entries(await buildSampleExport(await importMaintenancePublicKey(DEV_MAINTENANCE_PUBLIC_KEY)))) {
  mkdirSync(dirname(resolve(root, path)), { recursive: true });
  writeFileSync(resolve(root, path), data);
}

console.log(`Sample export written to ${root}`);
