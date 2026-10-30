/**
 * Decrypt an export (see export-format.ts) with the maintenance secret key.
 *
 * Runs in the browser (the maintenance tool) and in Node (the tests) alike: it
 * never touches a file system, it asks `readFile` for the ciphertexts it needs.
 * Each item is reported on its own, so one corrupt row neither stops the batch
 * nor hides the others; a child whose parent cannot be opened says so.
 *
 * An export may mix organizations: a deployment escrows each owner's resources
 * for the key covering their email domain. A root escrowed for another key, and
 * everything under it, is set aside with that key's fingerprint rather than
 * reported as damaged; export-writer.ts hands it back still encrypted, as an
 * export of its own for that key's custodians.
 */
import {
  base64ToUint8,
  decryptContent,
  maintenanceKeyIdToFingerprint,
  readMaintenanceCopyKeyId,
  uint8ToBase64,
  unwrapMaintenanceKey,
} from '@encryption/src/crypto';
import type { HybridSecretKey } from '@encryption/src/crypto';
import { type ExportItem, idKey } from '@encryption/src/maintenance/export-format';
import { DOMAIN_CONTENT, DOMAIN_WRAPPED_KEY } from '@encryption/src/shared/crypto-domains';
import { formatDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

/** A ciphertext file of the export, or `undefined` when the folder does not have it. */
export type ReadExportFile = (path: string) => Promise<Uint8Array | undefined>;

/** `otherKey`: the fingerprint of the maintenance key the item is escrowed for, when it is not this one. */
export type ItemResult = { item: ExportItem; ok: true; plaintext?: Uint8Array } | { item: ExportItem; ok: false; error: string; otherKey?: string };

/** A failure's reason, led by the stable code when there is one (libsodium's own messages are not). */
export function describeError(error: unknown): string {
  if (error instanceof VaultError) return `${error.code}: ${error.message}`;

  return error instanceof Error ? error.message : String(error);
}

class ParentError extends Error {}

/** A root escrowed for another maintenance key than the custodians': `fingerprint` names it. */
export class OtherKeyError extends Error {
  constructor(readonly fingerprint: string) {
    super(`escrowed for another maintenance key, ${formatDecimalFingerprint(fingerprint)}`);
  }
}

/** A root's key, out of its escrow copy; a copy made for another key throws OtherKeyError. */
export async function openRootCopy(key: { secretKey: HybridSecretKey; keyId: Uint8Array }, maintenanceKey: string): Promise<Uint8Array> {
  const copy = base64ToUint8(maintenanceKey);

  try {
    return await unwrapMaintenanceKey(key, copy);
  } catch (error) {
    if (error instanceof VaultError && error.code === VaultErrorCode.OTHER_MAINTENANCE_KEY) {
      throw new OtherKeyError(maintenanceKeyIdToFingerprint(readMaintenanceCopyKeyId(copy)));
    }

    throw error;
  }
}

/**
 * How many roots of an export a key's copies cover, read from the copies' headers
 * without opening any: a phrase that opens none of them is said before the run.
 * Null when no root has a readable header.
 */
export function copyCoverage(items: ExportItem[], fingerprint: string): { roots: number; ours: number } | null {
  let roots = 0;
  let ours = 0;

  for (const item of items) {
    if (item.maintenanceKey === undefined) continue;

    let itemFingerprint: string;

    try {
      itemFingerprint = maintenanceKeyIdToFingerprint(readMaintenanceCopyKeyId(base64ToUint8(item.maintenanceKey)));
    } catch {
      // A copy without a readable header is neither ours nor another key's: the run reports it as damaged.
      continue;
    }

    roots++;
    if (itemFingerprint === fingerprint) ours++;
  }

  return roots === 0 ? null : { roots, ours };
}

/**
 * The recovery of one export: each item on demand, the keys opened once and kept
 * (a key is 32 bytes, a plaintext can be gigabytes), so the tool can decrypt item
 * after item without holding the results, and decrypt one again to preview it.
 */
export function createRecovery(key: { secretKey: HybridSecretKey; keyId: Uint8Array }, items: ExportItem[], readFile: ReadExportFile) {
  const byId = new Map(items.map((item) => [idKey(item.id), item]));
  const keys = new Map<string, Promise<Uint8Array>>();

  // Memoized, so a document with a thousand attachments is unwrapped once; the
  // chain of ids being resolved catches an export whose parents loop.
  const keyOf = (item: ExportItem, chain: string[] = []): Promise<Uint8Array> => {
    let itemKey = keys.get(idKey(item.id));

    if (!itemKey) {
      itemKey = (async () => {
        if (item.maintenanceKey !== undefined) return openRootCopy(key, item.maintenanceKey);

        const parentId = idKey(item.parent as string | number);
        const parent = byId.get(parentId);

        if (!parent) throw new ParentError(`parent ${parentId} is not in the export`);
        if (chain.includes(parentId)) throw new ParentError(`parents loop: ${[...chain, idKey(item.id), parentId].join(' -> ')}`);

        let parentKey: Uint8Array;

        try {
          parentKey = await keyOf(parent, [...chain, idKey(item.id)]);
        } catch (error) {
          // A child goes where its root goes: set aside with it, or reported with it.
          throw error instanceof ParentError || error instanceof OtherKeyError ? error : new ParentError(`parent ${parentId} could not be opened`);
        }

        return item.wrappedKey === undefined ? parentKey : decryptContent(base64ToUint8(item.wrappedKey), parentKey, DOMAIN_WRAPPED_KEY);
      })();
      keys.set(idKey(item.id), itemKey);
    }

    return itemKey;
  };

  return {
    async recover(item: ExportItem): Promise<ItemResult> {
      try {
        const itemKey = await keyOf(item);
        let ciphertext: Uint8Array | undefined;

        if (item.content !== undefined) {
          ciphertext = base64ToUint8(item.content);
        } else if (item.file !== undefined) {
          ciphertext = await readFile(item.file);

          if (!ciphertext) throw new Error(`file ${item.file} is not in the export folder`);
        }

        return { item, ok: true, plaintext: ciphertext && (await decryptContent(ciphertext, itemKey, DOMAIN_CONTENT)) };
      } catch (error) {
        return error instanceof OtherKeyError
          ? { item, ok: false, error: error.message, otherKey: error.fingerprint }
          : { item, ok: false, error: describeError(error) };
      }
    },
  };
}

export async function* recoverItems(
  key: { secretKey: HybridSecretKey; keyId: Uint8Array },
  items: ExportItem[],
  readFile: ReadExportFile
): AsyncGenerator<ItemResult> {
  const recovery = createRecovery(key, items, readFile);

  for (const item of items) yield await recovery.recover(item);
}

/**
 * The line of the decrypted manifest for one result: the product's own fields as
 * they came, the key material dropped (nothing is encrypted any more), `content`
 * now the plaintext in base64, `file` the same path, now holding the plaintext.
 */
export function decryptedManifestLine(result: ItemResult): Record<string, unknown> {
  const { maintenanceKey: _maintenanceKey, wrappedKey: _wrappedKey, content, ...rest } = result.item;

  if (!result.ok) {
    const { file: _file, ...withoutFile } = rest;

    return { ...withoutFile, error: result.error };
  }

  return content !== undefined && result.plaintext ? { ...rest, content: uint8ToBase64(result.plaintext) } : rest;
}
