import { englishWordlist, frenchWordlist, keyToMnemonic, mnemonicLanguageForLocale, mnemonicToKey } from '@encryption/src/crypto/mnemonic';

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
