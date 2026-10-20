/**
 * Writes `src/maintenance/sample-export/`: the sample export (see testing.ts) as a
 * folder on disk, encrypted for the development maintenance phrase, the way a
 * product team hands one over. Committed, so anyone can open the maintenance tool
 * on it, and frozen, so `sample-export.test.ts` proves an export made once keeps
 * decrypting. Rewritten only when the export format changes on purpose:
 *
 *   npm run maintenance:sample-export
 *
 * The randomness is seeded, here only: running it again without a change rewrites
 * the same bytes, so the diff shows only what really changed. Keys and nonces
 * derived from a public seed are fine for fake content under the development
 * phrase, and nothing else ever goes through this script.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

let counter = 0;

// libsodium draws every random byte from here: replaced before it loads (hence the dynamic imports below).
Object.defineProperty(globalThis.crypto, 'getRandomValues', {
  configurable: true,
  value: <T extends ArrayBufferView>(array: T): T => {
    const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);

    for (let offset = 0; offset < bytes.length; offset += 32) {
      bytes.set(
        createHash('sha256')
          .update(`lasuite-maintenance-sample-export:${counter++}`)
          .digest()
          .subarray(0, bytes.length - offset),
        offset
      );
    }

    return array;
  },
});

const { importMaintenancePublicKey } = await import('@encryption/src/crypto/maintenance-escrow');
const { DEV_MAINTENANCE_PUBLIC_KEY } = await import('@encryption/src/maintenance/dev-maintenance-key');
const { buildSampleExport } = await import('@encryption/src/maintenance/testing');

const root = resolve(import.meta.dirname, 'sample-export');

rmSync(root, { recursive: true, force: true });

for (const [path, data] of Object.entries(await buildSampleExport(await importMaintenancePublicKey(DEV_MAINTENANCE_PUBLIC_KEY)))) {
  mkdirSync(dirname(resolve(root, path)), { recursive: true });
  writeFileSync(resolve(root, path), data);
}

console.log(`Sample export written to ${root}`);
