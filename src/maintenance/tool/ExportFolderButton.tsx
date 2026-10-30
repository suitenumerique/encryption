import type { PickedFile } from '@encryption/src/maintenance/tool/export-folder';

/**
 * The button that picks an export folder. Files are read when needed, one at a
 * time: picking a folder of gigabytes loads nothing.
 */
export function ExportFolderButton({ label, onPick }: { label: string; onPick: (files: PickedFile[]) => void }) {
  return (
    <label className="mt-button mt-file">
      {label}
      <input
        type="file"
        multiple
        ref={(input) => {
          if (input) input.webkitdirectory = true;
        }}
        onChange={(event) =>
          onPick(
            Array.from(event.target.files ?? []).map((file) => ({
              path: file.webkitRelativePath || file.name,
              read: async () => new Uint8Array(await file.arrayBuffer()),
            }))
          )
        }
      />
    </label>
  );
}
