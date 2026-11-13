/**
 * Re-wrap the escrow copies of an export for a new maintenance key: when an
 * organization replaces its key (new custodians, a phrase to retire), every copy
 * made for the old key is opened with the old phrase and wrapped again for the new
 * public key, before the old phrase is destroyed.
 *
 * Only roots carry a copy (their descendants are wrapped by their parent and do
 * not change), so a product exports its copies alone (`maintenance_export
 * --keys-only`). What comes out holds no secret, only copies wrapped for one
 * maintenance key or the other, so it can leave the isolated computer as it is.
 *
 * Each line keeps the input's fields and gets the new copy in `maintenanceKey`,
 * with the one it replaces in `previousMaintenanceKey`: the product writes the new
 * copy only where the stored one is still that previous copy (a compare-and-swap),
 * leaving alone a resource whose copy changed since the export.
 */
import { type MaintenancePublicKey, uint8ToBase64, wrapKeyForMaintenance } from '@encryption/src/crypto';
import type { HybridSecretKey } from '@encryption/src/crypto';
import { type ExportItem, MANIFEST_FILE } from '@encryption/src/maintenance/export-format';
import type { ExportSink } from '@encryption/src/maintenance/export-writer';
import { OtherKeyError, describeError, openRootCopy } from '@encryption/src/maintenance/recover';

export type RotationResult = { item: ExportItem; ok: true; copy: string } | { item: ExportItem; ok: false; error: string; otherKey?: string };

export async function* rotateCopies(
  oldKey: { secretKey: HybridSecretKey; keyId: Uint8Array },
  newKey: MaintenancePublicKey,
  items: ExportItem[]
): AsyncGenerator<RotationResult> {
  for (const item of items) {
    if (item.maintenanceKey === undefined) continue;

    try {
      const rootKey = await openRootCopy(oldKey, item.maintenanceKey);

      try {
        yield { item, ok: true, copy: uint8ToBase64(await wrapKeyForMaintenance(rootKey, newKey)) };
      } finally {
        rootKey.fill(0);
      }
    } catch (error) {
      yield error instanceof OtherKeyError
        ? { item, ok: false, error: describeError(error), otherKey: error.fingerprint }
        : { item, ok: false, error: describeError(error) };
    }
  }
}

/**
 * The line handed back for one root: the product's own fields, the new copy and
 * the one it replaces. The ciphertext a full export may carry on the same line
 * (`content`, `file`) is dropped: the rotation changes no content.
 */
export function rotatedManifestLine(result: RotationResult): Record<string, unknown> {
  const { maintenanceKey, content: _content, file: _file, ...rest } = result.item;

  return result.ok
    ? { ...rest, maintenanceKey: result.copy, previousMaintenanceKey: maintenanceKey }
    : { ...rest, previousMaintenanceKey: maintenanceKey, error: result.error };
}

export async function writeRotatedExport(
  results: AsyncIterable<RotationResult>,
  sink: ExportSink,
  onOutcome: (result: RotationResult) => void = () => undefined
): Promise<void> {
  const manifest = await sink.openManifest(MANIFEST_FILE);

  for await (const result of results) {
    await manifest.append(JSON.stringify(rotatedManifestLine(result)));
    onOutcome(result);
  }

  await manifest.close();
  await sink.close();
}
