import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { type MaintenanceKeyPair, maintenanceKeyIdToFingerprint, maintenanceKeyPairFromPhrase } from '@encryption/src/crypto/maintenance-escrow';
import { type ExportItem, ManifestError, parseManifest } from '@encryption/src/maintenance/export-format';
import { type ItemResult, decryptedExportEntries, recoverItems } from '@encryption/src/maintenance/recover';
import { type ExportFolder, openExportFolder } from '@encryption/src/maintenance/tool/export-folder';
import { previewOf } from '@encryption/src/maintenance/tool/preview';
import { ZipWriter } from '@encryption/src/maintenance/zip';
import { formatDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

type Archive = { url: string; name: string } | { error: string };

const PROGRESS_STEP = 25;
const MISSING_FILE_EXAMPLES = 3;

async function* replay(results: ItemResult[]): AsyncGenerator<ItemResult> {
  yield* results;
}

export function DecryptPanel() {
  const { t } = useTranslation('common');
  // `missingFiles`: named by the manifest but not in the folder, typically an
  // attachment not yet copied from the object storage. Said as soon as the folder
  // is picked, rather than as one failure per item after the decryption.
  const [opened, setOpened] = useState<{ folder: ExportFolder; items: ExportItem[]; missingFiles: string[] } | null>(null);
  const [folderError, setFolderError] = useState<string | null>(null);
  const [phrase, setPhrase] = useState('');
  // The verdict on a phrase, kept with the phrase it is about: a later keystroke
  // makes it stale without having to clear it.
  const [checked, setChecked] = useState<{ phrase: string; key: (MaintenanceKeyPair & { fingerprint: string }) | null } | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [results, setResults] = useState<ItemResult[] | null>(null);
  const [archive, setArchive] = useState<Archive | null>(null);
  const [previewing, setPreviewing] = useState<ItemResult | null>(null);

  const wordCount = phrase.trim() === '' ? 0 : phrase.trim().split(/\s+/).length;

  const current = wordCount === 24 && checked?.phrase === phrase ? checked : null;
  const key = current?.key ?? null;
  const phraseInvalid = current !== null && current.key === null;

  useEffect(() => {
    let cancelled = false;

    if (wordCount !== 24) return;

    void (async () => {
      try {
        const pair = await maintenanceKeyPairFromPhrase(phrase);

        if (!cancelled) setChecked({ phrase, key: { ...pair, fingerprint: maintenanceKeyIdToFingerprint(pair.keyId) } });
      } catch {
        if (!cancelled) setChecked({ phrase, key: null });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [phrase, wordCount]);

  useEffect(() => () => (archive && 'url' in archive ? URL.revokeObjectURL(archive.url) : undefined), [archive]);

  const reset = () => {
    setResults(null);
    setArchive(null);
    setPreviewing(null);
  };

  const pickFolder = async (fileList: FileList | null) => {
    reset();
    setOpened(null);
    setFolderError(null);

    const files = Array.from(fileList ?? []).map((file) => ({
      path: file.webkitRelativePath || file.name,
      read: async () => new Uint8Array(await file.arrayBuffer()),
    }));
    const folder = await openExportFolder(files);

    if (!folder) {
      setFolderError(t('maintenanceTool.decrypt.folderNoManifest'));

      return;
    }

    try {
      const items = parseManifest(folder.manifest);

      setOpened({
        folder,
        items,
        missingFiles: items.flatMap((item) => (item.file !== undefined && !folder.hasFile(item.file) ? [item.file] : [])),
      });
    } catch (error) {
      setFolderError(error instanceof ManifestError ? error.message : String(error));
    }
  };

  const run = async () => {
    if (!opened || !key) return;

    reset();

    const collected: ItemResult[] = [];
    const total = opened.items.length;

    setProgress({ done: 0, total });

    for await (const result of recoverItems(key, opened.items, opened.folder.readFile)) {
      collected.push(result);

      if (collected.length % PROGRESS_STEP === 0) setProgress({ done: collected.length, total });
    }

    setProgress(null);
    setResults(collected);

    try {
      const zip = new ZipWriter();

      for await (const entry of decryptedExportEntries(replay(collected), opened.folder.readFile)) zip.add(entry.path, entry.data);

      const url = URL.createObjectURL(new Blob(zip.finish() as BlobPart[], { type: 'application/zip' }));

      setArchive({ url, name: `${opened.folder.name}-decrypted.zip` });
    } catch (error) {
      setArchive({ error: error instanceof Error ? error.message : String(error) });
    }
  };

  const failed = results?.filter((result) => !result.ok && result.otherKey === undefined).length ?? 0;
  const otherKeys = new Map<string, number>();

  for (const result of results ?? []) {
    if (!result.ok && result.otherKey !== undefined) otherKeys.set(result.otherKey, (otherKeys.get(result.otherKey) ?? 0) + 1);
  }

  const otherCount = [...otherKeys.values()].reduce((sum, count) => sum + count, 0);

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
        <label className="mt-label" htmlFor="mt-phrase">
          {t('maintenanceTool.decrypt.phraseLabel')}
        </label>
        <textarea
          id="mt-phrase"
          className="mt-phrase"
          rows={4}
          value={phrase}
          onChange={(event) => setPhrase(event.target.value)}
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
        />
        {!key && !phraseInvalid && <p className="mt-help">{t('maintenanceTool.decrypt.phraseCount', { count: wordCount })}</p>}
        {phraseInvalid && (
          <p className="mt-error" role="alert">
            {t('maintenanceTool.decrypt.phraseInvalid')}
          </p>
        )}
        {key && (
          <p className="mt-status">
            {t('maintenanceTool.decrypt.fingerprint')} <code className="mt-fingerprint">{formatDecimalFingerprint(key.fingerprint)}</code>
          </p>
        )}
      </section>

      <section className="mt-step">
        <h2>{t('maintenanceTool.decrypt.runTitle')}</h2>
        <button type="button" className="mt-button mt-primary" disabled={!opened || !key || progress !== null} onClick={() => void run()}>
          {t('maintenanceTool.decrypt.run')}
        </button>
        {progress && (
          <p className="mt-status" role="status">
            {t('maintenanceTool.decrypt.running', progress)}
          </p>
        )}
        {results && (
          <>
            <p className={failed > 0 ? 'mt-error' : 'mt-status'} role="status">
              {t('maintenanceTool.decrypt.summary', { ok: results.length - failed - otherCount, failed })}
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
            {archive && 'url' in archive && (
              <>
                <a className="mt-button mt-primary" href={archive.url} download={archive.name}>
                  {t('maintenanceTool.decrypt.download')}
                </a>
                <p className="mt-warning">{t('maintenanceTool.decrypt.plaintextWarning')}</p>
              </>
            )}
            {archive && 'error' in archive && (
              <p className="mt-error" role="alert">
                {t('maintenanceTool.decrypt.zipFailed', { error: archive.error })}
              </p>
            )}
            <ResultTable results={results} onPreview={setPreviewing} />
          </>
        )}
      </section>

      {previewing?.ok && previewing.plaintext && <PreviewDialog result={previewing} onClose={() => setPreviewing(null)} />}
    </div>
  );
}

function ResultTable({ results, onPreview }: { results: ItemResult[]; onPreview: (result: ItemResult) => void }) {
  const { t } = useTranslation('common');

  return (
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
        {results.map((result) => (
          <tr key={result.item.id} className={result.ok ? undefined : result.otherKey !== undefined ? 'mt-row-other' : 'mt-row-failed'}>
            <td>
              <code>{result.item.id}</code>
            </td>
            <td>{result.item.type ?? ''}</td>
            <td>
              {result.ok
                ? result.plaintext
                  ? t('maintenanceTool.decrypt.ok')
                  : t('maintenanceTool.decrypt.keyOnly')
                : result.otherKey !== undefined
                  ? `${t('maintenanceTool.decrypt.otherKey')} (${formatDecimalFingerprint(result.otherKey)})`
                  : result.error}
            </td>
            <td>{result.ok && result.plaintext ? result.plaintext.length : ''}</td>
            <td>
              {result.ok && result.plaintext && (
                <button type="button" className="mt-link" onClick={() => onPreview(result)}>
                  {t('maintenanceTool.decrypt.preview')}
                </button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function PreviewDialog({ result, onClose }: { result: ItemResult & { ok: true }; onClose: () => void }) {
  const { t } = useTranslation('common');
  const plaintext = result.plaintext as Uint8Array;
  const preview = useMemo(() => previewOf(plaintext), [plaintext]);
  // A data: URL rather than an object URL: nothing to revoke, and still no request.
  const imageUrl = useMemo(() => (preview.kind === 'image' ? `data:${preview.mime};base64,${uint8ToBase64(plaintext)}` : null), [preview, plaintext]);

  return (
    <section className="mt-preview" aria-labelledby="mt-preview-title">
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
      {preview.kind === 'image' && imageUrl && <img className="mt-preview-image" src={imageUrl} alt={result.item.id} />}
      {preview.kind === 'binary' && (
        <p>
          {t('maintenanceTool.decrypt.previewBinary', {
            kind: t(`maintenanceTool.previewKinds.${preview.format}`),
            size: preview.size,
            head: preview.head,
          })}
        </p>
      )}
    </section>
  );
}
