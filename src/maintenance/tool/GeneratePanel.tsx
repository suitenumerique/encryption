import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  computeMaintenanceKeyFingerprint,
  exportMaintenancePublicKey,
  generateMaintenancePhrase,
  maintenanceKeyPairFromPhrase,
} from '@encryption/src/crypto/maintenance-escrow';
import { type MnemonicLanguage, mnemonicLanguageForLocale } from '@encryption/src/crypto/mnemonic';
import { PublicKeyView } from '@encryption/src/maintenance/tool/PublicKeyView';
import { formatDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

interface Generated {
  words: string[];
  publicKey: string;
  fingerprint: string;
  generatedAt: Date;
  phraseUrl: string;
}

type CopyState = 'idle' | 'copied' | 'failed';

/** `seed` makes the generated key fixed, for a reproducible demonstration; never set in the tool itself. */
export function GeneratePanel({ seed }: { seed?: Uint8Array }) {
  const { t, i18n } = useTranslation('common');
  const [language, setLanguage] = useState<MnemonicLanguage>(mnemonicLanguageForLocale(i18n.language));
  const [generated, setGenerated] = useState<Generated | null>(null);
  const [copy, setCopy] = useState<CopyState>('idle');
  const [confirming, setConfirming] = useState(false);
  // The question takes the focus, on its safe answer: a keyboard user hears it, and Enter does not generate by accident.
  const cancelButton = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (confirming) cancelButton.current?.focus();
  }, [confirming]);

  useEffect(
    () => () => {
      if (!generated) return;

      URL.revokeObjectURL(generated.phraseUrl);
    },
    [generated]
  );

  // The phrase as a text: the download, and what the copy puts on the clipboard.
  const phraseFile = (words: string[], fingerprint: string, generatedAt: Date) =>
    [
      t('maintenanceTool.generate.phraseFileTitle'),
      t('maintenanceTool.generate.phraseFileDate', { date: generatedAt.toISOString().slice(0, 10) }),
      t('maintenanceTool.generate.phraseFileFingerprint', { fingerprint: formatDecimalFingerprint(fingerprint) }),
      '',
      ...words.map((word, index) => `${index + 1}. ${word}`),
      '',
    ].join('\n');

  const generate = async () => {
    const phrase = await generateMaintenancePhrase(language, seed);
    const pair = await maintenanceKeyPairFromPhrase(phrase);
    const publicKey = exportMaintenancePublicKey(pair.publicKey);
    const fingerprint = await computeMaintenanceKeyFingerprint(publicKey);
    const words = phrase.split(' ');
    const generatedAt = new Date();

    setCopy('idle');
    setGenerated({
      words,
      publicKey,
      fingerprint,
      generatedAt,
      phraseUrl: URL.createObjectURL(new Blob([phraseFile(words, fingerprint, generatedAt)], { type: 'text/plain' })),
    });
  };

  const copyPhrase = async () => {
    if (!generated) return;

    try {
      await navigator.clipboard.writeText(phraseFile(generated.words, generated.fingerprint, generated.generatedAt));
      setCopy('copied');
    } catch {
      setCopy('failed');
    }
  };

  return (
    <div className="mt-panel">
      <p className="mt-help">{t('maintenanceTool.generate.help')}</p>
      <div className="mt-row">
        <label className="mt-label" htmlFor="mt-wordlist">
          {t('maintenanceTool.generate.wordlist')}
        </label>
        <select id="mt-wordlist" value={language} onChange={(event) => setLanguage(event.target.value as MnemonicLanguage)}>
          <option value="french">{t('maintenanceTool.generate.french')}</option>
          <option value="english">{t('maintenanceTool.generate.english')}</option>
        </select>
        <button type="button" className="mt-button mt-primary" disabled={confirming} onClick={() => setConfirming(true)}>
          {t('maintenanceTool.generate.button')}
        </button>
      </div>
      {/* A new phrase replaces nothing on the server: asked first, so an existing key is not forgotten for a new one by mistake. */}
      {confirming && (
        <section className="mt-confirm" role="alertdialog" aria-labelledby="mt-confirm-title">
          <h2 id="mt-confirm-title">{t('maintenanceTool.generate.confirmTitle')}</h2>
          <p>{t('maintenanceTool.generate.confirmText')}</p>
          {generated && <p className="mt-warning">{t('maintenanceTool.generate.confirmReplaceShown')}</p>}
          <div className="mt-row">
            <button
              type="button"
              className="mt-button mt-primary"
              onClick={() => {
                setConfirming(false);
                void generate();
              }}
            >
              {t('maintenanceTool.generate.confirm')}
            </button>
            <button type="button" className="mt-button" ref={cancelButton} onClick={() => setConfirming(false)}>
              {t('maintenanceTool.generate.cancel')}
            </button>
          </div>
        </section>
      )}

      {generated && (
        <>
          <section className="mt-step mt-printable">
            <h2>{t('maintenanceTool.generate.phraseTitle')}</h2>
            <p className="mt-print-only">
              {t('maintenanceTool.generate.phraseFileDate', { date: generated.generatedAt.toISOString().slice(0, 10) })}
            </p>
            <ol className="mt-words">
              {generated.words.map((word, index) => (
                <li key={index}>{word}</li>
              ))}
            </ol>
            <p className="mt-print-only">
              {t('maintenanceTool.generate.phraseFileFingerprint', { fingerprint: formatDecimalFingerprint(generated.fingerprint) })}
            </p>
            <p className="mt-help mt-no-print">{t('maintenanceTool.generate.phraseCopiesHelp')}</p>
            <div className="mt-row mt-no-print">
              <button type="button" className="mt-button" onClick={() => void copyPhrase()}>
                {t('maintenanceTool.generate.copyPhrase')}
              </button>
              <a className="mt-button" href={generated.phraseUrl} download="maintenance-phrase.txt">
                {t('maintenanceTool.generate.downloadPhrase')}
              </a>
              <button type="button" className="mt-button" onClick={() => window.print()}>
                {t('maintenanceTool.generate.printPhrase')}
              </button>
            </div>
            {copy === 'copied' && (
              <p className="mt-status mt-no-print" role="status">
                {t('maintenanceTool.generate.copied')}
              </p>
            )}
            {copy === 'failed' && (
              <p className="mt-error mt-no-print" role="alert">
                {t('maintenanceTool.generate.copyFailed')}
              </p>
            )}
          </section>
          <PublicKeyView title={t('maintenanceTool.generate.publicKeyTitle')} publicKey={generated.publicKey} fingerprint={generated.fingerprint} />
        </>
      )}
    </div>
  );
}
