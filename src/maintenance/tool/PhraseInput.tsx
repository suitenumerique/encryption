import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { type MaintenanceKeyPair, maintenanceKeyIdToFingerprint, maintenanceKeyPairFromPhrase } from '@encryption/src/crypto/maintenance-escrow';
import { englishWordlist, frenchWordlist } from '@encryption/src/crypto/mnemonic';

export const PHRASE_WORDS = 24;

export type PhraseKey = MaintenanceKeyPair & { fingerprint: string };

// BIP-39 compares words in NFKD, so an accent typed precomposed or combined is the same word.
const normalize = (word: string) => word.trim().toLowerCase().normalize('NFKD');
const KNOWN_WORDS = new Set([...frenchWordlist, ...englishWordlist].map(normalize));

/**
 * The 24 words, one box each, numbered as they are written on the sheet: a word
 * outside both wordlists is flagged where it is, rather than the whole phrase being
 * refused. Pasting or typing several words into a box fills the next boxes, so a
 * phrase copied from a file goes in at once.
 */
export function PhraseInput({ idPrefix, onKey }: { idPrefix: string; onKey: (key: PhraseKey | null) => void }) {
  const { t } = useTranslation('common');
  const [words, setWords] = useState<string[]>(() => Array(PHRASE_WORDS).fill(''));
  const [left, setLeft] = useState<Set<number>>(() => new Set());
  // The verdict on a phrase, kept with the phrase it is about: a later keystroke
  // makes it stale without having to clear it.
  const [checked, setChecked] = useState<{ phrase: string; key: PhraseKey | null } | null>(null);
  const inputs = useRef<(HTMLInputElement | null)[]>([]);

  const phrase = words.map(normalize).join(' ');
  const filled = words.filter((word) => word.trim() !== '').length;
  const unknown = useMemo(
    () => new Set(words.flatMap((word, index) => (word.trim() !== '' && !KNOWN_WORDS.has(normalize(word)) ? [index] : []))),
    [words]
  );
  const complete = filled === PHRASE_WORDS && unknown.size === 0;
  const current = complete && checked?.phrase === phrase ? checked : null;

  useEffect(() => {
    let cancelled = false;

    if (!complete) return;

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
  }, [complete, phrase]);

  const key = current?.key ?? null;

  useEffect(() => onKey(key), [key, onKey]);

  const change = (index: number, value: string) => {
    const parts = value.split(/\s+/);
    const next = [...words];
    let last = index;

    // One word typed, or a space after it (move on), or several pasted (spread them).
    parts.forEach((part, offset) => {
      if (part === '' && offset > 0) return;
      if (index + offset < PHRASE_WORDS) {
        next[index + offset] = part;
        last = index + offset;
      }
    });
    setWords(next);

    // Words that arrived together are complete: flag an unknown one at once.
    if (parts.length > 1) {
      setLeft((previous) => {
        const done = new Set(previous);

        for (let filledIndex = index; filledIndex <= last; filledIndex++) done.add(filledIndex);

        return done;
      });
    }

    if (parts.length > 1) inputs.current[Math.min(last + (parts.at(-1) === '' ? 1 : 0), PHRASE_WORDS - 1)]?.focus();
  };

  const clear = () => {
    setWords(Array(PHRASE_WORDS).fill(''));
    setLeft(new Set());
    inputs.current[0]?.focus();
  };

  return (
    <fieldset className="mt-phrase-input">
      <legend className="mt-label">{t('maintenanceTool.phrase.label')}</legend>
      <ol className="mt-phrase-grid">
        {words.map((word, index) => {
          const flagged = unknown.has(index) && left.has(index);

          return (
            <li key={index}>
              <label htmlFor={`${idPrefix}-word-${index}`}>{index + 1}</label>
              <input
                id={`${idPrefix}-word-${index}`}
                ref={(input) => {
                  inputs.current[index] = input;
                }}
                value={word}
                aria-label={t('maintenanceTool.phrase.word', { number: index + 1 })}
                aria-invalid={flagged || undefined}
                autoComplete="off"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                onChange={(event) => change(index, event.target.value)}
                onBlur={() => setLeft((previous) => new Set(previous).add(index))}
              />
            </li>
          );
        })}
      </ol>
      <div className="mt-row">
        <span className="mt-help">{t('maintenanceTool.phrase.count', { count: filled })}</span>
        <button type="button" className="mt-link" onClick={clear}>
          {t('maintenanceTool.phrase.clear')}
        </button>
      </div>
      {[...unknown].some((index) => left.has(index)) && (
        <p className="mt-error" role="alert">
          {t('maintenanceTool.phrase.unknownWords', {
            numbers: [...unknown]
              .filter((index) => left.has(index))
              .map((index) => index + 1)
              .join(', '),
          })}
        </p>
      )}
      {current && current.key === null && (
        <p className="mt-error" role="alert">
          {t('maintenanceTool.phrase.invalid')}
        </p>
      )}
    </fieldset>
  );
}
