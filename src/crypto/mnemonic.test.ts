import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  type MnemonicLanguage,
  detectMnemonicLanguage,
  englishWordlist,
  frenchWordlist,
  keyToMnemonic,
  mnemonicLanguageForLocale,
  mnemonicToKey,
} from '@encryption/src/crypto/mnemonic';

describe('mnemonic', () => {
  it('should encode a 32-byte key as 24 words', () => {
    const key = crypto.getRandomValues(new Uint8Array(32));

    expect(keyToMnemonic(key).split(' ')).toHaveLength(24);
  });

  it('should roundtrip encode/decode a key', () => {
    const key = crypto.getRandomValues(new Uint8Array(32));

    expect(mnemonicToKey(keyToMnemonic(key))).toEqual(key);
  });

  it('should produce different mnemonics for different keys', () => {
    const key1 = crypto.getRandomValues(new Uint8Array(32));
    const key2 = crypto.getRandomValues(new Uint8Array(32));

    expect(keyToMnemonic(key1)).not.toBe(keyToMnemonic(key2));
  });

  // Pinned vectors, NOT a round-trip. Every other test here encodes and decodes with
  // the same code, so all of them would still pass if the encoding itself moved, while
  // every recovery phrase a user already wrote down stopped working. These fix the
  // mapping to exact bytes so a library upgrade cannot change it silently.
  //
  // The French phrase is written with \u0301 escapes because BIP-39 mandates NFKD:
  // the wordlist emits "agre" + combining acute, not the precomposed "agréable" a
  // keyboard produces. The two are indistinguishable on screen, so the escapes keep
  // the distinction alive through editors, copy-paste and review.
  const KNOWN_KEY = new Uint8Array(Array.from({ length: 32 }, (_, index) => index));
  const KNOWN_ENGLISH =
    'abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware';
  const KNOWN_FRENCH =
    'abaisser agre\u0301able inductif agre\u0301able e\u0301ligible achat bolide boucle amateur exister de\u0301rober bison abrasif justice e\u0301charpe inonder avancer piano adulte cobra papaye anonyme hangar tomate';

  it('encodes a known key to the exact phrases users have written down', () => {
    expect(keyToMnemonic(KNOWN_KEY, 'english')).toBe(KNOWN_ENGLISH);
    expect(keyToMnemonic(KNOWN_KEY, 'french')).toBe(KNOWN_FRENCH);
  });

  it('decodes those same phrases back to the known key', () => {
    expect(mnemonicToKey(KNOWN_ENGLISH, 'english')).toEqual(KNOWN_KEY);
    expect(mnemonicToKey(KNOWN_FRENCH, 'french')).toEqual(KNOWN_KEY);
  });

  it('should support French and English', () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const fr = keyToMnemonic(key, 'french');
    const en = keyToMnemonic(key, 'english');

    expect(fr).not.toBe(en);
    expect(mnemonicToKey(fr, 'french')).toEqual(key);
    expect(mnemonicToKey(en, 'english')).toEqual(key);
  });

  it('maps interface locales to a wordlist language (regional codes included)', () => {
    expect(mnemonicLanguageForLocale('fr')).toBe('french');
    expect(mnemonicLanguageForLocale('fr-FR')).toBe('french'); // regional locale must NOT fall through to English
    expect(mnemonicLanguageForLocale('FR')).toBe('french');
    expect(mnemonicLanguageForLocale('en')).toBe('english');
    expect(mnemonicLanguageForLocale('en-GB')).toBe('english');
    expect(mnemonicLanguageForLocale('de')).toBe('english'); // unsupported -> default
  });

  it('should auto-detect language when not specified', () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const fr = keyToMnemonic(key, 'french');

    expect(mnemonicToKey(fr)).toEqual(key);
  });

  it('should reject corrupted mnemonic', () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const words = keyToMnemonic(key).split(' ');
    const idx = frenchWordlist.indexOf(words[23]);
    words[23] = frenchWordlist[(idx + 1) % frenchWordlist.length];

    expect(() => mnemonicToKey(words.join(' '))).toThrow();
  });

  it('should be case-insensitive', () => {
    const key = crypto.getRandomValues(new Uint8Array(32));

    expect(mnemonicToKey(keyToMnemonic(key).toUpperCase())).toEqual(key);
  });

  it('should have no duplicate words in the French wordlist', () => {
    expect(new Set(frenchWordlist).size).toBe(2048);
  });

  it('should have no duplicate words in the English wordlist', () => {
    expect(new Set(englishWordlist).size).toBe(2048);
  });
});

describe('mnemonic round trip (property)', () => {
  const key = fc.uint8Array({ minLength: 32, maxLength: 32 });
  const language = fc.constantFrom<MnemonicLanguage>('french', 'english');
  // The ways a phrase gets mangled between a printed kit and an input field.
  const mangle = fc.record({
    upper: fc.boolean(),
    separator: fc.constantFrom(' ', '  ', '\t', '\n', ' \n '),
    padding: fc.constantFrom('', ' ', '\n\t'),
    nfc: fc.boolean(),
  });

  it('decodes back to the same key however the phrase was typed, with or without a language hint', () => {
    fc.assert(
      fc.property(key, language, mangle, (k, lang, m) => {
        let phrase = keyToMnemonic(k, lang).split(' ').join(m.separator);
        if (m.upper) phrase = phrase.toUpperCase();
        if (m.nfc) phrase = phrase.normalize('NFC');
        phrase = m.padding + phrase + m.padding;

        expect(mnemonicToKey(phrase)).toEqual(k);
        expect(mnemonicToKey(phrase, lang)).toEqual(k);
        expect(detectMnemonicLanguage(phrase)).toBe(lang);
      })
    );
  });

  it('rejects a phrase with any single word swapped for another wordlist entry', () => {
    fc.assert(
      fc.property(key, language, fc.nat(), fc.nat(), (k, lang, wordIndex, replacementIndex) => {
        const wordlist = lang === 'french' ? frenchWordlist : englishWordlist;
        const words = keyToMnemonic(k, lang).split(' ');
        const i = wordIndex % 24;
        const replacement = wordlist[replacementIndex % wordlist.length];
        fc.pre(replacement !== words[i]);
        words[i] = replacement;

        // One word carries 11 bits and the checksum only 8, so a swap can
        // survive it with probability 1/256: the result must then be a
        // DIFFERENT key, never the original one.
        let decoded: Uint8Array;
        try {
          decoded = mnemonicToKey(words.join(' '), lang);
        } catch {
          return;
        }
        expect(decoded).not.toEqual(k);
      })
    );
  });
});
