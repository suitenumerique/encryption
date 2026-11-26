import { MANIFEST_FILE } from '@encryption/src/maintenance/export-format';
import type { ReadExportFile } from '@encryption/src/maintenance/recover';

/** A file as the browser hands it from a folder picker, or a test hands it. */
export interface PickedFile {
  /** `webkitRelativePath`: the picked folder's name, then the path inside it. */
  path: string;
  read(): Promise<Uint8Array>;
}

export interface ExportFolder {
  name: string;
  manifest: string;
  fileCount: number;
  hasFile(path: string): boolean;
  readFile: ReadExportFile;
}

/** Several exports at the same depth: which one was meant cannot be guessed. */
export class SeveralExportsError extends Error {
  constructor(readonly folders: string[]) {
    super(`Several exports side by side: ${folders.join(', ')}`);
  }
}

/**
 * Locate the export inside what was picked: the folder holding the shallowest
 * manifest.ndjson is the root, so picking the export folder itself or the folder
 * just above it both work. Paths in the manifest are relative to that root.
 * Throws SeveralExportsError when two manifests share the shallowest depth.
 */
export async function openExportFolder(files: PickedFile[]): Promise<ExportFolder | null> {
  const depth = (path: string) => path.split('/').length;
  const manifests = files
    .filter((file) => file.path === MANIFEST_FILE || file.path.endsWith(`/${MANIFEST_FILE}`))
    .sort((a, b) => depth(a.path) - depth(b.path));

  if (manifests.length === 0) return null;

  const shallowest = manifests.filter((file) => depth(file.path) === depth(manifests[0].path));

  if (shallowest.length > 1) throw new SeveralExportsError(shallowest.map((file) => file.path.slice(0, -MANIFEST_FILE.length - 1)));

  const root = manifests[0].path.slice(0, -MANIFEST_FILE.length);
  const byPath = new Map(files.filter((file) => file.path.startsWith(root)).map((file) => [file.path.slice(root.length), file]));

  return {
    name: root.replace(/\/$/, '').split('/').pop() || MANIFEST_FILE,
    manifest: new TextDecoder().decode(await manifests[0].read()),
    fileCount: byPath.size - 1,
    hasFile: (path) => byPath.has(path),
    readFile: async (path) => byPath.get(path)?.read(),
  };
}
