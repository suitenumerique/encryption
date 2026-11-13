/**
 * Where the decrypted copy goes, from the best the browser offers to the least:
 *
 *   - a FOLDER the custodians pick (File System Access API: Chrome, Edge), written
 *     file by file: nothing to unzip, no limit but the disk's;
 *   - a ZIP archive streamed into the browser's private storage (the origin
 *     private file system: Firefox, which has no folder picker), then downloaded
 *     from there, so neither the archive nor its files are ever whole in memory;
 *   - a ZIP archive in memory, where neither exists: bounded by the memory.
 *
 * Each item's plaintext is written and dropped before the next is decrypted, so
 * the first two hold one item at a time, whatever the export weighs.
 */
import {
  type DirectoryHandle,
  type ExportSink,
  type Spool,
  type WritableFile,
  folderSink,
  memorySpool,
  zipSink,
} from '@encryption/src/maintenance/export-writer';

interface FileHandle {
  createWritable(): Promise<WritableFile>;
  getFile(): Promise<File>;
}

interface StorageDirectory {
  getFileHandle(name: string, options: { create: boolean }): Promise<FileHandle>;
  removeEntry(name: string): Promise<void>;
  keys(): AsyncIterable<string>;
}

interface PickedDirectory extends DirectoryHandle {
  name: string;
}

declare global {
  interface Window {
    showDirectoryPicker?: (options: { mode: 'readwrite'; id?: string }) => Promise<PickedDirectory>;
  }
}

export class OutputExistsError extends Error {}

// Every temporary file this tool puts in the browser's storage starts with it, so
// those a closed tab left behind are found and deleted.
const STORAGE_PREFIX = 'lasuite-maintenance-';

export const canWriteFolder = () => typeof window.showDirectoryPicker === 'function';

/**
 * A new folder named `name` inside the one the custodians pick: never written into
 * an existing folder, so nothing already there is overwritten or mixed in.
 */
export async function pickOutputFolder(name: string): Promise<{ sink: ExportSink; label: string }> {
  const parent = await window.showDirectoryPicker!({ mode: 'readwrite', id: 'lasuite-maintenance' });
  let exists = true;

  try {
    await parent.getDirectoryHandle(name, { create: false });
  } catch {
    exists = false;
  }

  if (exists) throw new OutputExistsError(`${parent.name}/${name}`);

  return { sink: folderSink(await parent.getDirectoryHandle(name, { create: true })), label: `${parent.name}/${name}` };
}

async function storageDirectory(): Promise<StorageDirectory | null> {
  try {
    const root = (await navigator.storage?.getDirectory?.()) as unknown as StorageDirectory | undefined;

    return root ?? null;
  } catch {
    // Chrome refuses it to a page opened from a file.
    return null;
  }
}

/** Deletes what an earlier run left in the browser's storage (a tab closed before its archive was deleted). */
export async function deleteLeftovers(): Promise<void> {
  const root = await storageDirectory();

  if (!root) return;

  const names: string[] = [];

  for await (const name of root.keys()) if (name.startsWith(STORAGE_PREFIX)) names.push(name);
  for (const name of names) await root.removeEntry(name).catch(() => undefined);
}

export interface ZipOutput {
  sink: ExportSink;
  /** The finished archive, once the sink is closed. */
  archive(): Promise<Blob>;
  /** Deletes the archive from the browser's storage; nothing to do for one in memory. */
  discard(): Promise<void>;
  inBrowserStorage: boolean;
}

export async function zipOutput(): Promise<ZipOutput> {
  const root = await storageDirectory();
  const random = () => Math.random().toString(36).slice(2);

  if (root) {
    const name = `${STORAGE_PREFIX}${random()}.zip`;
    const handle = await root.getFileHandle(name, { create: true });
    const spools: string[] = [];

    const newSpool = async (): Promise<Spool> => {
      const spoolName = `${STORAGE_PREFIX}${random()}.spool`;
      const spoolHandle = await root.getFileHandle(spoolName, { create: true });
      const writable = await spoolHandle.createWritable();

      spools.push(spoolName);

      return {
        append: (data) => writable.write(data),
        chunks: async function* () {
          await writable.close();

          const reader = (await spoolHandle.getFile()).stream().getReader();

          for (;;) {
            const { done, value } = await reader.read();

            if (done) return;

            yield value;
          }
        },
        dispose: () => root.removeEntry(spoolName),
      };
    };

    return {
      sink: zipSink(await handle.createWritable(), newSpool),
      // A File from the storage reads from disk: downloading it does not load it.
      archive: () => handle.getFile(),
      discard: async () => {
        for (const spool of spools) await root.removeEntry(spool).catch(() => undefined);
        await root.removeEntry(name).catch(() => undefined);
      },
      inBrowserStorage: true,
    };
  }

  const parts: Uint8Array[] = [];

  return {
    sink: zipSink({ write: async (data) => void parts.push(data), close: async () => undefined }, async () => memorySpool()),
    archive: async () => new Blob(parts as BlobPart[], { type: 'application/zip' }),
    discard: async () => void parts.splice(0),
    inBrowserStorage: false,
  };
}

/**
 * A manifest alone, in memory, to download: the output of a rotation, which holds
 * no file and no secret (only copies wrapped for a maintenance key).
 */
export function manifestInMemory(): { sink: ExportSink; file(): Blob } {
  const parts: Uint8Array[] = [];

  return {
    sink: {
      writeFile: async (path) => {
        throw new Error(`a manifest alone has no file: ${path}`);
      },
      openManifest: async () => ({ append: async (line) => void parts.push(new TextEncoder().encode(`${line}\n`)), close: async () => undefined }),
      close: async () => undefined,
    },
    file: () => new Blob(parts as BlobPart[], { type: 'application/x-ndjson' }),
  };
}
