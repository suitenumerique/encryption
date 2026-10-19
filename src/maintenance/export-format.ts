/**
 * The export a product hands to the maintenance tool: one folder, the same shape
 * for every product, so there is one tool and no per-product code.
 *
 *   export/
 *     manifest.ndjson         one JSON object per line, one line per encrypted item
 *     <any/relative/path>     ciphertexts too large or too binary for a column
 *                             (attachments from object storage), named by `file`
 *
 * An item is anything encrypted: a document, an attachment, a comment, a Drive
 * folder or file. Its KEY comes from exactly one place:
 *
 *   - `maintenanceKey`: a root resource, whose key the maintenance phrase opens;
 *   - `parent` + `wrappedKey`: its own key, wrapped by the parent item's key (an
 *     attachment under its document, a Drive item under its folder);
 *   - `parent` alone: encrypted directly with the parent item's key.
 *
 * Its CIPHERTEXT, when it has one, is `content` (base64, straight from a column)
 * or `file` (a path inside the export folder). An item with neither only carries
 * a key for its children, like a Drive folder.
 *
 * Every other field passes through untouched into the decrypted manifest, so the
 * product can carry what its write-back needs (a title, an `updatedAt` to detect
 * an edit made after the export...).
 */
import { z } from 'zod';

import '@encryption/src/shared/zod-jitless';

export const MANIFEST_FILE = 'manifest.ndjson';

/** Where the decrypted export puts the items of other keys: `other-keys/<fingerprint>/`, an export folder each. */
export const OTHER_KEYS_FOLDER = 'other-keys';

// PostgreSQL's encode(..., 'base64') breaks lines every 76 characters; decoding
// that as-is would silently produce garbage, so it is refused with the fix.
const base64 = z
  .string()
  .min(1)
  .regex(/^[A-Za-z0-9+/]+={0,2}$/, "expected base64 on a single line (PostgreSQL's encode() wraps it: use translate(encode(...), E'\\n', ''))");

// Ids come from whatever the product's primary keys are: uuids, or integers. They
// go back out with the type they came in, so the product's write-back matches its
// own keys; `idKey` is how they are compared (a parent "7" is the item 7).
const id = z.union([z.string().min(1), z.number().int()]);

export const idKey = (value: string | number): string => String(value);

// Relative, forward slashes, no way out of the export folder.
const relativePath = z
  .string()
  .min(1)
  .refine(
    (path) => !path.startsWith('/') && !path.includes('\\') && path.split('/').every((part) => part !== '' && part !== '.' && part !== '..'),
    'expected a relative path inside the export folder (forward slashes, no "..")'
  )
  .refine((path) => path !== MANIFEST_FILE, `the manifest itself (${MANIFEST_FILE}) cannot be an item's file`)
  .refine(
    (path) => path.split('/')[0].toLowerCase() !== OTHER_KEYS_FOLDER,
    `${OTHER_KEYS_FOLDER}/ is where the decrypted export sets aside other keys' items`
  );

export const exportItemSchema = z
  .looseObject({
    id,
    type: z.string().min(1).optional(),
    maintenanceKey: base64.optional(),
    parent: id.optional(),
    wrappedKey: base64.optional(),
    content: base64.optional(),
    file: relativePath.optional(),
  })
  .superRefine((item, ctx) => {
    if ((item.maintenanceKey === undefined) === (item.parent === undefined)) {
      ctx.addIssue({ code: 'custom', message: 'needs exactly one of maintenanceKey (a root) or parent (a nested item)' });
    }

    if (item.wrappedKey !== undefined && item.parent === undefined) {
      ctx.addIssue({ code: 'custom', path: ['wrappedKey'], message: 'a wrappedKey is unwrapped by its parent: parent is required' });
    }

    if (item.content !== undefined && item.file !== undefined) {
      ctx.addIssue({ code: 'custom', message: 'content and file are two places for the same ciphertext: give one' });
    }
  });

export type ExportItem = z.infer<typeof exportItemSchema>;

export class ManifestError extends Error {}

/**
 * Parse the whole manifest, or refuse it: an export with a malformed line is a
 * broken export, and decrypting the rest would hide that. Blank lines and CRLF
 * endings (an export written on Windows) are tolerated.
 */
export function parseManifest(text: string): ExportItem[] {
  const items: ExportItem[] = [];
  const seen = new Set<string>();
  // Two items naming one file would write their plaintexts to the same path: the
  // second would overwrite the first in a folder, and fail the whole archive.
  // Compared without case, as the custodians' file system may well do.
  const files = new Set<string>();

  text.split(/\r?\n/).forEach((line, index) => {
    if (line.trim() === '') return;

    let raw: unknown;

    try {
      raw = JSON.parse(line);
    } catch {
      throw new ManifestError(`line ${index + 1}: not a JSON object on one line`);
    }

    const parsed = exportItemSchema.safeParse(raw);

    if (!parsed.success) {
      throw new ManifestError(`line ${index + 1}: ${z.prettifyError(parsed.error)}`);
    }

    if (seen.has(idKey(parsed.data.id))) {
      throw new ManifestError(`line ${index + 1}: id ${parsed.data.id} appears twice`);
    }

    const file = parsed.data.file?.toLowerCase();

    if (file !== undefined && files.has(file)) {
      throw new ManifestError(`line ${index + 1}: file ${parsed.data.file} is named by two items`);
    }

    seen.add(idKey(parsed.data.id));

    if (file !== undefined) files.add(file);

    items.push(parsed.data);
  });

  return items;
}
