import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  computeMaintenanceKeyFingerprint,
  exportMaintenancePublicKey,
  generateMaintenancePhrase,
  maintenanceKeyPairFromPhrase,
} from '@encryption/src/crypto/maintenance-escrow';
import { type MnemonicLanguage, mnemonicLanguageForLocale } from '@encryption/src/crypto/mnemonic';
import { formatDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

interface Generated {
  words: string[];
  publicKey: string;
  fingerprint: string;
  generatedAt: Date;
  publicKeyUrl: string;
  phraseUrl: string;
}

type CopyState = 'idle' | 'copied' | 'failed';

/** `seed` makes the generated key fixed, for a reproducible demonstration; never set in the tool itself. */
export function GeneratePanel({ seed }: { seed?: Uint8Array }) {
  const { t, i18n } = useTranslation('common');
  const [language, setLanguage] = useState<MnemonicLanguage>(mnemonicLanguageForLocale(i18n.language));
  const [generated, setGenerated] = useState<Generated | null>(null);
  const [copy, setCopy] = useState<CopyState>('idle');

  useEffect(
    () => () => {
      if (!generated) return;

      URL.revokeObjectURL(generated.publicKeyUrl);
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
      publicKeyUrl: URL.createObjectURL(new Blob([`${publicKey}\n`], { type: 'text/plain' })),
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
        <button type="button" className="mt-button mt-primary" onClick={() => void generate()}>
          {t('maintenanceTool.generate.button')}
        </button>
      </div>

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
          <section className="mt-step">
            <h2>{t('maintenanceTool.generate.publicKeyTitle')}</h2>
            <textarea
              className="mt-public-key"
              readOnly
              rows={6}
              value={generated.publicKey}
              aria-label={t('maintenanceTool.generate.publicKeyTitle')}
            />
            <a className="mt-button" href={generated.publicKeyUrl} download="maintenance-public-key.txt">
              {t('maintenanceTool.generate.downloadPublicKey')}
            </a>
            <p className="mt-status">
              {t('maintenanceTool.generate.fingerprint')} <code className="mt-fingerprint">{formatDecimalFingerprint(generated.fingerprint)}</code>
            </p>
          </section>
        </>
      )}
    </div>
  );
}
