import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { type MaintenancePublicKey, importMaintenancePublicKey, maintenanceKeyIdToFingerprint } from '@encryption/src/crypto/maintenance-escrow';
import { type ExportItem, ManifestError, parseManifest } from '@encryption/src/maintenance/export-format';
import type { ExportSink } from '@encryption/src/maintenance/export-writer';
import { copyCoverage } from '@encryption/src/maintenance/recover';
import { type RotationResult, rotateCopies, writeRotatedExport } from '@encryption/src/maintenance/rotate';
import { ExportFolderButton } from '@encryption/src/maintenance/tool/ExportFolderButton';
import { Fingerprint } from '@encryption/src/maintenance/tool/Fingerprint';
import { PhraseInput, type PhraseKey } from '@encryption/src/maintenance/tool/PhraseInput';
import { type PickedFile, SeveralExportsError, openExportFolder } from '@encryption/src/maintenance/tool/export-folder';
import { OutputExistsError, canWriteFolder, manifestInMemory, pickOutputFolder } from '@encryption/src/maintenance/tool/output';

const PROGRESS_INTERVAL_MS = 100;

type NewKey = (MaintenancePublicKey & { fingerprint: string }) | { error: string };
type Written = { kind: 'folder'; label: string } | { kind: 'download'; url: string; name: string } | { kind: 'error'; message: string };

/**
 * The rotation of an organization's copies to its new maintenance key: the export
 * of the copies alone, the current phrase, the new public key; out comes the same
 * manifest with each copy wrapped again for the new key (rotate.ts). Nothing secret
 * comes out, so unlike a decrypted copy it needs no care on the way back.
 */
export function RotatePanel() {
  const { t } = useTranslation('common');
  const [opened, setOpened] = useState<{ name: string; items: ExportItem[] } | null>(null);
  const [folderError, setFolderError] = useState<string | null>(null);
  const [oldKey, setOldKey] = useState<PhraseKey | null>(null);
  const [newKeyText, setNewKeyText] = useState('');
  const [newKey, setNewKey] = useState<NewKey | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [results, setResults] = useState<{ ok: number; failed: number; otherKeys: number } | null>(null);
  const [written, setWritten] = useState<Written | null>(null);

  const reset = () => {
    setResults(null);
    setWritten((previous) => {
      if (previous?.kind === 'download') URL.revokeObjectURL(previous.url);

      return null;
    });
  };

  const pickFolder = async (files: PickedFile[]) => {
    reset();
    setOpened(null);
    setFolderError(null);

    try {
      const folder = await openExportFolder(files);

      if (!folder) {
        setFolderError(t('maintenanceTool.decrypt.folderNoManifest'));

        return;
      }

      setOpened({ name: folder.name, items: parseManifest(folder.manifest) });
    } catch (error) {
      if (error instanceof SeveralExportsError) {
        setFolderError(t('maintenanceTool.decrypt.folderSeveralExports', { folders: error.folders.join(', ') }));
      } else {
        setFolderError(error instanceof ManifestError ? error.message : String(error));
      }
    }
  };

  const readNewKey = async (text: string) => {
    reset();
    setNewKeyText(text);

    if (text.trim() === '') {
      setNewKey(null);

      return;
    }

    try {
      const key = await importMaintenancePublicKey(text.trim());

      setNewKey({ ...key, fingerprint: maintenanceKeyIdToFingerprint(key.keyId) });
    } catch (error) {
      setNewKey({ error: error instanceof Error ? error.message : String(error) });
    }
  };

  const validNewKey = newKey && !('error' in newKey) ? newKey : null;
  const sameKey = validNewKey !== null && oldKey !== null && validNewKey.fingerprint === oldKey.fingerprint;
  const roots = opened ? opened.items.filter((item) => item.maintenanceKey !== undefined).length : 0;
  const coverage = useMemo(() => (opened && oldKey ? copyCoverage(opened.items, oldKey.fingerprint) : null), [opened, oldKey]);
  const ready = opened !== null && oldKey !== null && validNewKey !== null && !sameKey && progress === null;

  const rotateInto = async (sink: ExportSink) => {
    if (!opened || !oldKey || !validNewKey) return;

    const counts = { ok: 0, failed: 0, otherKeys: 0 };
    let done = 0;
    let shownAt = 0;

    setProgress({ done, total: roots });

    try {
      await writeRotatedExport(rotateCopies(oldKey, validNewKey, opened.items), sink, (result: RotationResult) => {
        done++;
        if (result.ok) counts.ok++;
        else if (result.otherKey !== undefined) counts.otherKeys++;
        else counts.failed++;

        if (performance.now() - shownAt >= PROGRESS_INTERVAL_MS) {
          shownAt = performance.now();
          setProgress({ done, total: roots });
        }
      });
    } finally {
      setProgress(null);
      setResults(counts);
    }
  };

  const failure = (error: unknown) =>
    setWritten({
      kind: 'error',
      message: t('maintenanceTool.rotate.outputFailed', { error: error instanceof Error ? error.message : String(error) }),
    });

  const runIntoFolder = async () => {
    if (!opened) return;

    reset();

    let picked: { sink: ExportSink; label: string };

    try {
      picked = await pickOutputFolder(`${opened.name}-rotated`);
    } catch (error) {
      if (error instanceof OutputExistsError)
        setWritten({ kind: 'error', message: t('maintenanceTool.decrypt.outputExists', { folder: error.message }) });

      return;
    }

    try {
      await rotateInto(picked.sink);
      setWritten({ kind: 'folder', label: picked.label });
    } catch (error) {
      failure(error);
    }
  };

  const runIntoDownload = async () => {
    reset();

    const output = manifestInMemory();

    try {
      await rotateInto(output.sink);
      setWritten({ kind: 'download', url: URL.createObjectURL(output.file()), name: 'manifest.ndjson' });
    } catch (error) {
      failure(error);
    }
  };

  return (
    <div className="mt-panel">
      <p className="mt-help">{t('maintenanceTool.rotate.help')}</p>

      <section className="mt-step">
        <h2>{t('maintenanceTool.rotate.folderTitle')}</h2>
        <p className="mt-help">{t('maintenanceTool.rotate.folderHelp')}</p>
        <ExportFolderButton label={t('maintenanceTool.decrypt.folderButton')} onPick={(files) => void pickFolder(files)} />
        {opened && (
          <p className="mt-status" role="status">
            {t('maintenanceTool.rotate.folderSummary', { folder: opened.name, count: roots })}
          </p>
        )}
        {folderError && (
          <p className="mt-error" role="alert">
            {folderError}
          </p>
        )}
      </section>

      <section className="mt-step">
        <h2>{t('maintenanceTool.rotate.oldPhraseTitle')}</h2>
        <p className="mt-help">{t('maintenanceTool.rotate.oldPhraseHelp')}</p>
        <PhraseInput idPrefix="mt-rotate" onKey={setOldKey} />
        {oldKey && <Fingerprint fingerprint={oldKey.fingerprint} help={t('maintenanceTool.decrypt.fingerprint')} />}
      </section>

      <section className="mt-step">
        <h2>{t('maintenanceTool.rotate.newKeyTitle')}</h2>
        <p className="mt-help">{t('maintenanceTool.rotate.newKeyHelp')}</p>
        <textarea
          className="mt-public-key"
          aria-label={t('maintenanceTool.rotate.newKeyTitle')}
          rows={4}
          spellCheck={false}
          value={newKeyText}
          onChange={(event) => void readNewKey(event.target.value)}
        />
        {newKey && 'error' in newKey && (
          <p className="mt-error" role="alert">
            {t('maintenanceTool.rotate.newKeyInvalid', { error: newKey.error })}
          </p>
        )}
        {validNewKey && <Fingerprint fingerprint={validNewKey.fingerprint} help={t('maintenanceTool.rotate.newKeyFingerprint')} />}
        {sameKey && (
          <p className="mt-alert" role="alert">
            {t('maintenanceTool.rotate.sameKey')}
          </p>
        )}
      </section>

      <section className="mt-step">
        <h2>{t('maintenanceTool.rotate.runTitle')}</h2>
        {coverage && coverage.ours === 0 && (
          <p className="mt-alert" role="alert">
            {t('maintenanceTool.decrypt.coverageNone', { roots: coverage.roots })}
          </p>
        )}
        {coverage && coverage.ours > 0 && coverage.ours < coverage.roots && (
          <p className="mt-warning" role="status">
            {t('maintenanceTool.rotate.coverageSome', coverage)}
          </p>
        )}
        <div className="mt-row">
          {canWriteFolder() && (
            <button type="button" className="mt-button mt-primary" disabled={!ready} onClick={() => void runIntoFolder()}>
              {t('maintenanceTool.rotate.runFolder')}
            </button>
          )}
          <button
            type="button"
            className={canWriteFolder() ? 'mt-button' : 'mt-button mt-primary'}
            disabled={!ready}
            onClick={() => void runIntoDownload()}
          >
            {t('maintenanceTool.rotate.runDownload')}
          </button>
        </div>
        {progress && (
          <div className="mt-progress" role="status">
            <progress max={progress.total} value={progress.done} aria-label={t('maintenanceTool.rotate.runTitle')} />
            <span>{t('maintenanceTool.rotate.running', { done: progress.done, total: progress.total })}</span>
          </div>
        )}
        {written?.kind === 'error' && (
          <p className="mt-error" role="alert">
            {written.message}
          </p>
        )}
        {results && (
          <>
            <p className={results.failed > 0 ? 'mt-error' : 'mt-status'} role="status">
              {t('maintenanceTool.rotate.summary', { ok: results.ok, failed: results.failed })}
            </p>
            {results.otherKeys > 0 && (
              <p className="mt-warning" role="alert">
                {t('maintenanceTool.rotate.otherKeys', { count: results.otherKeys })}
              </p>
            )}
            {written?.kind === 'folder' && <p className="mt-status">{t('maintenanceTool.decrypt.writtenTo', { folder: written.label })}</p>}
            {written?.kind === 'download' && (
              <div className="mt-row">
                <a className="mt-button mt-primary" href={written.url} download={written.name}>
                  {t('maintenanceTool.rotate.download')}
                </a>
              </div>
            )}
            {written && written.kind !== 'error' && <p className="mt-help">{t('maintenanceTool.rotate.noSecret')}</p>}
          </>
        )}
      </section>
    </div>
  );
}
