import { useCallback, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { englishWordlist, frenchWordlist } from '@encryption/src/crypto/mnemonic';

// A word is "known" if it belongs to either supported BIP-39 wordlist, so we can
// flag obvious typos without forcing the user to pick a language first.
const KNOWN_WORDS = new Set<string>([...englishWordlist, ...frenchWordlist]);

interface RecoveryPhraseInputProps {
  wordCount?: number;
  // Emits the joined, normalized phrase plus whether every box is filled, so the
  // caller can keep its submit button disabled until the phrase is complete.
  onChange: (phrase: string, complete: boolean) => void;
}

/**
 * A grid of one-word inputs for entering a recovery phrase, in the style of
 * MetaMask/Bitwarden: space (or a completed word) advances to the next box,
 * Backspace on an empty box steps back, and pasting the whole phrase into any
 * box distributes it across the grid. Each box turns red when its word is not in
 * the wordlist, catching typos before submission. The words are masked (like a
 * password) by default, with a toggle to reveal them, so the phrase is not
 * shoulder-surfable while typing.
 */
export function RecoveryPhraseInput({ wordCount = 24, onChange }: RecoveryPhraseInputProps) {
  const { t } = useTranslation('common');
  const [words, setWords] = useState<string[]>(() => Array(wordCount).fill(''));
  const [revealed, setRevealed] = useState(false);
  // A box is validated (and may turn red) only once it has been left (blurred),
  // so the user is not told a word is wrong while still typing it.
  const [touched, setTouched] = useState<boolean[]>(() => Array(wordCount).fill(false));
  const refs = useRef<Array<HTMLInputElement | null>>([]);

  const markTouched = useCallback((index: number) => {
    setTouched((prev) => {
      if (prev[index]) return prev;
      const next = [...prev];
      next[index] = true;

      return next;
    });
  }, []);

  const emit = useCallback(
    (next: string[]) => {
      setWords(next);
      onChange(
        next.join(' ').trim().replace(/\s+/g, ' '),
        next.every((w) => w.length > 0)
      );
    },
    [onChange]
  );

  const focus = useCallback(
    (i: number) => {
      refs.current[Math.max(0, Math.min(i, wordCount - 1))]?.focus();
    },
    [wordCount]
  );

  const handleChange = useCallback(
    (index: number, raw: string) => {
      // Split on whitespace and drop any list-numbering tokens ("1.", "2)", "13"),
      // so a numbered recovery sheet pastes back cleanly.
      const parts = raw
        .trim()
        .split(/\s+/)
        .filter((p) => p && !/^\d+[.)]?$/.test(p));

      // Pasting (or typing) several words at once fans them out across the grid.
      if (parts.length > 1) {
        const next = [...words];
        parts.forEach((p, k) => {
          if (index + k < wordCount) next[index + k] = p.toLowerCase();
        });
        emit(next);
        focus(index + parts.length);

        return;
      }

      const next = [...words];
      next[index] = raw.trim().toLowerCase();
      emit(next);
    },
    [words, wordCount, emit, focus]
  );

  const handleKeyDown = useCallback(
    (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === ' ' || e.key === 'Enter') {
        // Space marks a word complete -> jump to the next box.
        e.preventDefault();
        if (words[index]) focus(index + 1);
      } else if (e.key === 'Backspace' && words[index] === '' && index > 0) {
        e.preventDefault();
        focus(index - 1);
      } else if (e.key === 'ArrowLeft' && index > 0 && e.currentTarget.selectionStart === 0) {
        e.preventDefault();
        focus(index - 1);
      } else if (e.key === 'ArrowRight' && index < wordCount - 1 && e.currentTarget.selectionStart === words[index].length) {
        e.preventDefault();
        focus(index + 1);
      }
    },
    [words, wordCount, focus]
  );

  const indices = useMemo(() => Array.from({ length: wordCount }, (_, i) => i), [wordCount]);
  const hasInvalidWord = words.some((w, i) => touched[i] && w.length > 0 && !KNOWN_WORDS.has(w));

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 8 }}>
        <button
          type="button"
          onClick={() => setRevealed((v) => !v)}
          aria-pressed={revealed}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 4,
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            fontSize: 13,
            color: 'var(--c--globals--colors--brand-400, #000091)',
          }}
        >
          <span className="material-icons" style={{ fontSize: 18 }}>
            {revealed ? 'visibility_off' : 'visibility'}
          </span>
          {revealed ? t('onboarding.hide_words') : t('onboarding.reveal_words')}
        </button>
      </div>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(120px, 1fr))',
          gap: 8,
        }}
      >
        {indices.map((i) => {
          const invalid = touched[i] && words[i].length > 0 && !KNOWN_WORDS.has(words[i]);

          return (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 11, color: 'var(--c--contextuals--content--surface--secondary, #888)', width: 18, textAlign: 'right' }}>
                {i + 1}
              </span>
              <input
                ref={(el) => {
                  refs.current[i] = el;
                }}
                type={revealed ? 'text' : 'password'}
                inputMode="text"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                value={words[i]}
                onChange={(e) => handleChange(i, e.target.value)}
                onKeyDown={(e) => handleKeyDown(i, e)}
                onBlur={() => markTouched(i)}
                aria-label={`word ${i + 1}`}
                style={{
                  width: '100%',
                  boxSizing: 'border-box',
                  fontFamily: 'monospace',
                  fontSize: 13,
                  padding: '6px 8px',
                  borderRadius: 4,
                  border: `1px solid ${invalid ? 'var(--c--globals--colors--error-500, #ce0500)' : 'var(--c--contextuals--border--surface--primary, #e5e5e5)'}`,
                }}
              />
            </div>
          );
        })}
      </div>
      {hasInvalidWord && (
        <p style={{ fontSize: 12, color: 'var(--c--globals--colors--error-500, #ce0500)', margin: '8px 0 0' }}>{t('onboarding.invalid_word_hint')}</p>
      )}
    </div>
  );
}
