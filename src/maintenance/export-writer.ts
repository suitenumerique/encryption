/**
 * Writes the decrypted export as the recovery goes, item after item, so that only
 * the item being handled is ever in memory: its plaintext is written, then let go.
 * Where it goes is the sink's business: a folder the custodians picked, a ZIP
 * archive streamed into a temporary file, or, as a last resort, memory.
 *
 * The output mirrors the input (see export-format.ts): the decrypted manifest
 * with each `file` holding its plaintext, and the items of other keys, untouched,
 * in an export folder per key under `other-keys/<fingerprint>/`.
 */
import { MANIFEST_FILE, OTHER_KEYS_FOLDER } from '@encryption/src/maintenance/export-format';
import { type ItemResult, type ReadExportFile, decryptedManifestLine } from '@encryption/src/maintenance/recover';
import { ZipWriter } from '@encryption/src/maintenance/zip';

/** A manifest being written, one line at a time. */
export interface ManifestWriter {
  append(line: string): Promise<void>;
  close(): Promise<void>;
}

export interface ExportSink {
  writeFile(path: string, data: Uint8Array): Promise<void>;
  openManifest(path: string): Promise<ManifestWriter>;
  close(): Promise<void>;
}

/** What `writeDecryptedExport` keeps of each item: its outcome, never its plaintext. */
type WithoutPlaintext<T> = T extends unknown ? Omit<T, 'plaintext'> : never;

export type ItemOutcome = WithoutPlaintext<ItemResult> & { size?: number };

const encoder = new TextEncoder();

export async function writeDecryptedExport(
  results: AsyncIterable<ItemResult>,
  readFile: ReadExportFile,
  sink: ExportSink,
  onOutcome: (outcome: ItemOutcome) => void = () => undefined
): Promise<void> {
  const manifest = await sink.openManifest(MANIFEST_FILE);
  const otherKeys = new Map<string, ManifestWriter>();

  for await (const result of results) {
    if (!result.ok && result.otherKey !== undefined) {
      const folder = `${OTHER_KEYS_FOLDER}/${result.otherKey}`;
      let otherManifest = otherKeys.get(result.otherKey);

      if (!otherManifest) {
        otherManifest = await sink.openManifest(`${folder}/${MANIFEST_FILE}`);
        otherKeys.set(result.otherKey, otherManifest);
      }

      const ciphertext = result.item.file !== undefined ? await readFile(result.item.file) : undefined;

      if (ciphertext) await sink.writeFile(`${folder}/${result.item.file}`, ciphertext);

      await otherManifest.append(JSON.stringify(result.item));
      onOutcome(result);
      continue;
    }

    if (result.ok && result.item.file !== undefined && result.plaintext) {
      await sink.writeFile(result.item.file, result.plaintext);
    }

    await manifest.append(JSON.stringify(decryptedManifestLine(result)));

    const { plaintext, ...outcome } = result as ItemResult & { plaintext?: Uint8Array };

    onOutcome(plaintext ? { ...outcome, size: plaintext.length } : outcome);
  }

  for (const otherManifest of otherKeys.values()) await otherManifest.close();
  await manifest.close();
  await sink.close();
}

// ---------------------------------------------------------------------------
// A folder (the File System Access API, Chrome and Edge)
// ---------------------------------------------------------------------------

/** The part of a FileSystemDirectoryHandle the folder sink uses, so tests can stand in for it. */
export interface DirectoryHandle {
  getDirectoryHandle(name: string, options: { create: boolean }): Promise<DirectoryHandle>;
  getFileHandle(name: string, options: { create: boolean }): Promise<{ createWritable(): Promise<WritableFile> }>;
}

export interface WritableFile {
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
}

/** Writes the export into `root` as a tree of plain files: nothing to unzip, no size limit but the disk's. */
export function folderSink(root: DirectoryHandle): ExportSink {
  const directories = new Map<string, Promise<DirectoryHandle>>([['', Promise.resolve(root)]]);

  const directoryOf = (path: string): Promise<DirectoryHandle> => {
    let directory = directories.get(path);

    if (!directory) {
      const slash = path.lastIndexOf('/');

      directory = directoryOf(path.slice(0, Math.max(slash, 0))).then((parent) => parent.getDirectoryHandle(path.slice(slash + 1), { create: true }));
      directories.set(path, directory);
    }

    return directory;
  };

  const open = async (path: string): Promise<WritableFile> => {
    const slash = path.lastIndexOf('/');
    const directory = await directoryOf(slash === -1 ? '' : path.slice(0, slash));

    return (await directory.getFileHandle(path.slice(slash + 1), { create: true })).createWritable();
  };

  return {
    async writeFile(path, data) {
      const file = await open(path);

      await file.write(data);
      await file.close();
    },
    async openManifest(path) {
      const file = await open(path);

      return { append: (line) => file.write(encoder.encode(`${line}\n`)), close: () => file.close() };
    },
    async close() {},
  };
}

// ---------------------------------------------------------------------------
// A ZIP archive, streamed into whatever `output` stores it in
// ---------------------------------------------------------------------------

/**
 * Where a manifest waits while the files are written: an archive holds its
 * entries one after the other, so the manifests, complete only at the end, are
 * held aside (in a temporary file when there is one) and copied in last.
 */
export interface Spool {
  append(data: Uint8Array): Promise<void>;
  chunks(): AsyncIterable<Uint8Array>;
  dispose(): Promise<void>;
}

export function memorySpool(): Spool {
  const parts: Uint8Array[] = [];

  return {
    append: async (data) => void parts.push(data),
    chunks: async function* () {
      yield* parts;
    },
    dispose: async () => void parts.splice(0),
  };
}

export function zipSink(output: WritableFile, newSpool: () => Promise<Spool>, date = new Date()): ExportSink {
  const zip = new ZipWriter(date);
  const manifests: { path: string; spool: Spool }[] = [];
  const write = async (parts: Uint8Array[]) => {
    for (const part of parts) await output.write(part);
  };

  return {
    writeFile: (path, data) => write(zip.add(path, data)),
    async openManifest(path) {
      const spool = await newSpool();

      manifests.push({ path, spool });

      return { append: (line) => spool.append(encoder.encode(`${line}\n`)), close: async () => undefined };
    },
    async close() {
      // The main manifest was opened first: written last, as an unzip tool lists it.
      for (const { path, spool } of manifests.reverse()) {
        for await (const part of zip.addStream(path, spool.chunks())) await output.write(part);

        await spool.dispose();
      }

      await write(zip.finish());
      await output.close();
    },
  };
}
