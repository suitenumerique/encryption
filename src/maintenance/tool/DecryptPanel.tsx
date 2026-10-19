import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { type ExportItem, ManifestError, parseManifest } from '@encryption/src/maintenance/export-format';
import { type ExportSink, type ItemOutcome, writeDecryptedExport } from '@encryption/src/maintenance/export-writer';
import { type ItemResult, createRecovery, recoverItems } from '@encryption/src/maintenance/recover';
import { PhraseInput, type PhraseKey } from '@encryption/src/maintenance/tool/PhraseInput';
import { type ExportFolder, SeveralExportsError, openExportFolder } from '@encryption/src/maintenance/tool/export-folder';
import { formatSize } from '@encryption/src/maintenance/tool/format-size';
import {
  OutputExistsError,
  type ZipOutput,
  canWriteFolder,
  deleteLeftovers,
  pickOutputFolder,
  zipOutput,
} from '@encryption/src/maintenance/tool/output';
import { previewOf } from '@encryption/src/maintenance/tool/preview';
import { formatDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

type Written = { kind: 'folder'; label: string } | { kind: 'zip'; url: string; name: string; output: ZipOutput } | { kind: 'error'; message: string };

const PROGRESS_STEP = 25;
const MISSING_FILE_EXAMPLES = 3;
// A preview decrypts the item again, whole: past this size, open it from the output instead.
const PREVIEW_LIMIT = 50_000_000;

export function DecryptPanel() {
  const { t, i18n } = useTranslation('common');
  // `missingFiles`: named by the manifest but not in the folder, typically an
  // attachment not yet copied from the object storage. Said as soon as the folder
  // is picked, rather than as one failure per item after the decryption.
  const [opened, setOpened] = useState<{ folder: ExportFolder; items: ExportItem[]; missingFiles: string[] } | null>(null);
  const [folderError, setFolderError] = useState<string | null>(null);
  const [key, setKey] = useState<PhraseKey | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  // Outcomes only: the plaintexts went to the output as they were decrypted.
  const [outcomes, setOutcomes] = useState<ItemOutcome[] | null>(null);
  const [written, setWritten] = useState<Written | null>(null);
  const [previewing, setPreviewing] = useState<ItemResult | { item: ExportItem; tooLarge: number } | null>(null);
  const recovery = useRef<ReturnType<typeof createRecovery> | null>(null);

  // A tab closed earlier may have left a decrypted archive in the browser's storage.
  useEffect(() => void deleteLeftovers(), []);

  useEffect(
    () => () => {
      if (written?.kind !== 'zip') return;

      URL.revokeObjectURL(written.url);
      void written.output.discard();
    },
    [written]
  );

  // While a decrypted archive sits in the browser's storage, leaving the page asks
  // first, and leaving anyway deletes it on the way out. Should the tab die before
  // that, the next opening of the page deletes what is left (deleteLeftovers).
  useEffect(() => {
    if (written?.kind !== 'zip' || !written.output.inBrowserStorage) return;

    const output = written.output;
    const ask = (event: BeforeUnloadEvent) => event.preventDefault();
    const discard = () => void output.discard();

    window.addEventListener('beforeunload', ask);
    window.addEventListener('pagehide', discard);

    return () => {
      window.removeEventListener('beforeunload', ask);
      window.removeEventListener('pagehide', discard);
    };
  }, [written]);

  const reset = () => {
    setOutcomes(null);
    setWritten(null);
    setPreviewing(null);
    recovery.current = null;
  };

  const pickFolder = async (fileList: FileList | null) => {
    reset();
    setOpened(null);
    setFolderError(null);

    // Read when needed, one file at a time: picking the folder loads nothing.
    const files = Array.from(fileList ?? []).map((file) => ({
      path: file.webkitRelativePath || file.name,
      read: async () => new Uint8Array(await file.arrayBuffer()),
    }));
    try {
      const folder = await openExportFolder(files);

      if (!folder) {
        setFolderError(t('maintenanceTool.decrypt.folderNoManifest'));

        return;
      }

      const items = parseManifest(folder.manifest);

      setOpened({
        folder,
        items,
        missingFiles: items.flatMap((item) => (item.file !== undefined && !folder.hasFile(item.file) ? [item.file] : [])),
      });
    } catch (error) {
      if (error instanceof SeveralExportsError) {
        setFolderError(t('maintenanceTool.decrypt.folderSeveralExports', { folders: error.folders.join(', ') }));
      } else {
        setFolderError(error instanceof ManifestError ? error.message : String(error));
      }
    }
  };

  const decryptInto = async (sink: ExportSink) => {
    if (!opened || !key) return;

    const collected: ItemOutcome[] = [];
    const total = opened.items.length;

    setProgress({ done: 0, total });

    try {
      await writeDecryptedExport(recoverItems(key, opened.items, opened.folder.readFile), opened.folder.readFile, sink, (outcome) => {
        collected.push(outcome);

        if (collected.length % PROGRESS_STEP === 0) setProgress({ done: collected.length, total });
      });
      recovery.current = createRecovery(key, opened.items, opened.folder.readFile);
    } finally {
      setProgress(null);
      setOutcomes(collected);
    }
  };

  const runIntoFolder = async () => {
    if (!opened) return;

    reset();

    let picked: { sink: ExportSink; label: string };

    try {
      picked = await pickOutputFolder(`${opened.folder.name}-decrypted`);
    } catch (error) {
      if (error instanceof OutputExistsError)
        setWritten({ kind: 'error', message: t('maintenanceTool.decrypt.outputExists', { folder: error.message }) });

      // Otherwise the picker was cancelled: nothing to say.
      return;
    }

    try {
      await decryptInto(picked.sink);
      setWritten({ kind: 'folder', label: picked.label });
    } catch (error) {
      setWritten({
        kind: 'error',
        message: t('maintenanceTool.decrypt.outputFailed', { error: error instanceof Error ? error.message : String(error) }),
      });
    }
  };

  const runIntoZip = async () => {
    if (!opened) return;

    reset();

    const output = await zipOutput();

    try {
      await decryptInto(output.sink);

      const url = URL.createObjectURL(await output.archive());

      setWritten({ kind: 'zip', url, name: `${opened.folder.name}-decrypted.zip`, output });
    } catch (error) {
      await output.discard();
      setWritten({
        kind: 'error',
        message: t('maintenanceTool.decrypt.outputFailed', { error: error instanceof Error ? error.message : String(error) }),
      });
    }
  };

  const preview = async (outcome: ItemOutcome) => {
    if ((outcome.size ?? 0) > PREVIEW_LIMIT) {
      setPreviewing({ item: outcome.item, tooLarge: outcome.size as number });

      return;
    }

    const result = await recovery.current?.recover(outcome.item);

    if (result) setPreviewing(result);
  };

  const discardArchive = () => {
    if (written?.kind === 'zip') setWritten(null);
  };

  const failed = outcomes?.filter((outcome) => !outcome.ok && outcome.otherKey === undefined).length ?? 0;
  const otherKeys = new Map<string, number>();

  for (const outcome of outcomes ?? []) {
    if (!outcome.ok && outcome.otherKey !== undefined) otherKeys.set(outcome.otherKey, (otherKeys.get(outcome.otherKey) ?? 0) + 1);
  }

  const otherCount = [...otherKeys.values()].reduce((sum, count) => sum + count, 0);
  const ready = opened !== null && key !== null && progress === null;

  return (
    <div className="mt-panel">
      <section className="mt-step">
        <h2>{t('maintenanceTool.decrypt.folderTitle')}</h2>
        <p className="mt-help">{t('maintenanceTool.decrypt.folderHelp')}</p>
        <label className="mt-button mt-file">
          {t('maintenanceTool.decrypt.folderButton')}
          <input
            type="file"
            multiple
            ref={(input) => {
              if (input) input.webkitdirectory = true;
            }}
            onChange={(event) => void pickFolder(event.target.files)}
          />
        </label>
        {opened && (
          <p className="mt-status" role="status">
            {t('maintenanceTool.decrypt.folderSummary', { folder: opened.folder.name, items: opened.items.length, files: opened.folder.fileCount })}
          </p>
        )}
        {opened && opened.missingFiles.length > 0 && (
          <p className="mt-warning" role="alert">
            {t('maintenanceTool.decrypt.folderMissingFiles', {
              count: opened.missingFiles.length,
              examples: opened.missingFiles.slice(0, MISSING_FILE_EXAMPLES).join(', '),
            })}
          </p>
        )}
        {folderError && (
          <p className="mt-error" role="alert">
            {folderError}
          </p>
        )}
      </section>

      <section className="mt-step">
        <h2>{t('maintenanceTool.decrypt.phraseTitle')}</h2>
        <p className="mt-help">{t('maintenanceTool.decrypt.phraseHelp')}</p>
        <PhraseInput idPrefix="mt-decrypt" onKey={setKey} />
        {key && (
          <p className="mt-status">
            {t('maintenanceTool.decrypt.fingerprint')} <code className="mt-fingerprint">{formatDecimalFingerprint(key.fingerprint)}</code>
          </p>
        )}
      </section>

      <section className="mt-step">
        <h2>{t('maintenanceTool.decrypt.runTitle')}</h2>
        <p className="mt-help">{t(canWriteFolder() ? 'maintenanceTool.decrypt.runHelpFolder' : 'maintenanceTool.decrypt.runHelpZip')}</p>
        <div className="mt-row">
          {canWriteFolder() && (
            <button type="button" className="mt-button mt-primary" disabled={!ready} onClick={() => void runIntoFolder()}>
              {t('maintenanceTool.decrypt.runFolder')}
            </button>
          )}
          <button
            type="button"
            className={canWriteFolder() ? 'mt-button' : 'mt-button mt-primary'}
            disabled={!ready}
            onClick={() => void runIntoZip()}
          >
            {t('maintenanceTool.decrypt.runZip')}
          </button>
        </div>
        {progress && (
          <p className="mt-status" role="status">
            {t('maintenanceTool.decrypt.running', progress)}
          </p>
        )}
        {written?.kind === 'error' && (
          <p className="mt-error" role="alert">
            {written.message}
          </p>
        )}
        {outcomes && (
          <>
            <p className={failed > 0 ? 'mt-error' : 'mt-status'} role="status">
              {t('maintenanceTool.decrypt.summary', { ok: outcomes.length - failed - otherCount, failed })}
            </p>
            {otherKeys.size > 0 && (
              <div className="mt-status">
                <p>{t('maintenanceTool.decrypt.otherKeys', { count: otherCount })}</p>
                <ul>
                  {[...otherKeys].map(([fingerprint, count]) => (
                    <li key={fingerprint}>
                      {t('maintenanceTool.decrypt.otherKeyGroup', { fingerprint: formatDecimalFingerprint(fingerprint), count })}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {written?.kind === 'folder' && <p className="mt-status">{t('maintenanceTool.decrypt.writtenTo', { folder: written.label })}</p>}
            {written?.kind === 'zip' && (
              <div className="mt-row">
                <a className="mt-button mt-primary" href={written.url} download={written.name}>
                  {t('maintenanceTool.decrypt.download')}
                </a>
                {written.output.inBrowserStorage && (
                  <button type="button" className="mt-button" onClick={discardArchive}>
                    {t('maintenanceTool.decrypt.discardArchive')}
                  </button>
                )}
              </div>
            )}
            {written?.kind === 'zip' && written.output.inBrowserStorage && <p className="mt-help">{t('maintenanceTool.decrypt.archiveInBrowser')}</p>}
            {written && written.kind !== 'error' && <p className="mt-warning">{t('maintenanceTool.decrypt.plaintextWarning')}</p>}
            <ResultTable outcomes={outcomes} onPreview={(outcome) => void preview(outcome)} />
          </>
        )}
      </section>

      {previewing && 'tooLarge' in previewing && (
        <p className="mt-warning" role="alert">
          {t('maintenanceTool.decrypt.previewTooLarge', { id: previewing.item.id, size: formatSize(previewing.tooLarge, i18n.language) })}
        </p>
      )}
      {previewing && 'ok' in previewing && previewing.ok && previewing.plaintext && (
        <PreviewDialog key={previewing.item.id} result={previewing} onClose={() => setPreviewing(null)} />
      )}
    </div>
  );
}

// Pages of rows rather than one table of the whole export: an export of a hundred
// thousand items would otherwise be as many rows in the page.
const PAGE_SIZE = 100;

function ResultTable({ outcomes, onPreview }: { outcomes: ItemOutcome[]; onPreview: (outcome: ItemOutcome) => void }) {
  const { t, i18n } = useTranslation('common');
  const [onlyFailures, setOnlyFailures] = useState(false);
  const [page, setPage] = useState(0);
  const shown = onlyFailures ? outcomes.filter((outcome) => !outcome.ok) : outcomes;
  const lastPage = Math.max(0, Math.ceil(shown.length / PAGE_SIZE) - 1);
  const current = Math.min(page, lastPage);
  const rows = shown.slice(current * PAGE_SIZE, (current + 1) * PAGE_SIZE);

  return (
    <>
      <div className="mt-row">
        <label>
          <input
            type="checkbox"
            checked={onlyFailures}
            onChange={(event) => {
              setOnlyFailures(event.target.checked);
              setPage(0);
            }}
          />{' '}
          {t('maintenanceTool.decrypt.onlyFailures')}
        </label>
        {shown.length > PAGE_SIZE && (
          <span className="mt-pages">
            <button type="button" className="mt-link" disabled={current === 0} onClick={() => setPage(current - 1)}>
              {t('maintenanceTool.decrypt.previousPage')}
            </button>
            <span>
              {t('maintenanceTool.decrypt.pageRange', {
                from: current * PAGE_SIZE + 1,
                to: current * PAGE_SIZE + rows.length,
                total: shown.length,
              })}
            </span>
            <button type="button" className="mt-link" disabled={current === lastPage} onClick={() => setPage(current + 1)}>
              {t('maintenanceTool.decrypt.nextPage')}
            </button>
          </span>
        )}
      </div>
      <table className="mt-table">
        <thead>
          <tr>
            <th>{t('maintenanceTool.decrypt.columns.id')}</th>
            <th>{t('maintenanceTool.decrypt.columns.type')}</th>
            <th>{t('maintenanceTool.decrypt.columns.result')}</th>
            <th>{t('maintenanceTool.decrypt.columns.size')}</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map((result) => (
            <tr key={result.item.id} className={result.ok ? undefined : result.otherKey !== undefined ? 'mt-row-other' : 'mt-row-failed'}>
              <td>
                <code>{result.item.id}</code>
              </td>
              <td className="mt-nowrap">{result.item.type ?? ''}</td>
              <td>
                {result.ok
                  ? result.size !== undefined
                    ? t('maintenanceTool.decrypt.ok')
                    : t('maintenanceTool.decrypt.keyOnly')
                  : result.otherKey !== undefined
                    ? `${t('maintenanceTool.decrypt.otherKey')} (${formatDecimalFingerprint(result.otherKey)})`
                    : result.error}
              </td>
              <td className="mt-size">{result.size !== undefined ? formatSize(result.size, i18n.language) : ''}</td>
              <td className="mt-nowrap">
                {result.size !== undefined && (
                  <button type="button" className="mt-link" onClick={() => onPreview(result)}>
                    {t('maintenanceTool.decrypt.preview')}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

// Beside the table from this width, over it below.
const SIDE_PREVIEW_QUERY = '(min-width: 1200px)';

/**
 * A panel beside the table on a wide window, which stays usable behind it; a modal
 * dialog over it on a narrow one, where there is no room beside.
 */
function PreviewDialog({ result, onClose }: { result: ItemResult & { ok: true }; onClose: () => void }) {
  const { t, i18n } = useTranslation('common');
  const dialog = useRef<HTMLDialogElement>(null);
  const plaintext = result.plaintext as Uint8Array;
  const preview = useMemo(() => previewOf(plaintext), [plaintext]);
  // A data: URL rather than an object URL: nothing to revoke, and still no request.
  const imageUrl = useMemo(() => (preview.kind === 'image' ? `data:${preview.mime};base64,${uint8ToBase64(plaintext)}` : null), [preview, plaintext]);

  const [side] = useState(() => window.matchMedia(SIDE_PREVIEW_QUERY).matches);
  // The latest close handler, read when needed: the parent's changes every render,
  // and re-running the effect would close and reopen the dialog each time.
  const closeRef = useRef(onClose);

  useEffect(() => {
    closeRef.current = onClose;
  });

  useEffect(() => {
    const element = dialog.current;

    if (side) element?.show();
    else element?.showModal();

    // Escape closes a modal dialog by itself, not a panel shown beside the page.
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') closeRef.current();
    };

    if (side) document.addEventListener('keydown', closeOnEscape);

    return () => {
      document.removeEventListener('keydown', closeOnEscape);
      element?.close();
    };
  }, [side]);

  return (
    <dialog ref={dialog} className={side ? 'mt-preview mt-preview-side' : 'mt-preview'} aria-labelledby="mt-preview-title" onClose={onClose}>
      <header>
        <h2 id="mt-preview-title">{t('maintenanceTool.decrypt.previewTitle', { id: result.item.id })}</h2>
        <button type="button" className="mt-link" onClick={onClose}>
          {t('maintenanceTool.decrypt.closePreview')}
        </button>
      </header>
      {preview.kind === 'text' && (
        <>
          <pre className="mt-preview-text">{preview.text}</pre>
          {preview.truncated && <p className="mt-help">{t('maintenanceTool.decrypt.previewTruncated')}</p>}
        </>
      )}
      {preview.kind === 'image' && imageUrl && <img className="mt-preview-image" src={imageUrl} alt={String(result.item.id)} />}
      {preview.kind === 'binary' && (
        <p>
          {t('maintenanceTool.decrypt.previewBinary', {
            kind: t(`maintenanceTool.previewKinds.${preview.format}`),
            size: formatSize(preview.size, i18n.language),
            head: preview.head,
          })}
        </p>
      )}
    </dialog>
  );
}
