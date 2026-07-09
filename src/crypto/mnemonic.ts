/**
 * Mnemonic encoder/decoder for AES-256 keys (32 bytes), BIP-39 compatible.
 *
 * Uses @scure/bip39 — a secure, audited implementation.
 * The version is pinned in package.json to ensure wordlists
 * don't change over time (which would break existing mnemonics).
 *
 * Vite's tree-shaking ensures only the imported functions and their
 * dependencies end up in the final bundle.
 */
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist as english } from '@scure/bip39/wordlists/english';
import { wordlist as french } from '@scure/bip39/wordlists/french';

import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

export type MnemonicLanguage = 'french' | 'english';

export { french as frenchWordlist, english as englishWordlist };

/**
 * Pick the BIP-39 wordlist language from an interface locale (an i18next code
 * like `fr`, `fr-FR`, `en`, `en-GB`). Prefix-matched, so a regional locale still
 * resolves to the base language; anything non-French falls back to English.
 */
export function mnemonicLanguageForLocale(locale: string): MnemonicLanguage {
  return locale.toLowerCase().startsWith('fr') ? 'french' : 'english';
}

function getWordlist(language: MnemonicLanguage): string[] {
  return language === 'french' ? french : english;
}

/**
 * Encode a 32-byte AES key as a 24-word BIP-39 mnemonic phrase.
 */
export function keyToMnemonic(keyBytes: Uint8Array, language: MnemonicLanguage = 'french'): string {
  if (keyBytes.length !== 32) {
    throw new VaultError(VaultErrorCode.INVALID_MNEMONIC, 'Key must be 32 bytes');
  }

  return entropyToMnemonic(keyBytes, getWordlist(language));
}

/**
 * Decode a BIP-39 mnemonic phrase back to a 32-byte AES key.
 * Validates the checksum. If a language is provided, uses it directly.
 * Otherwise, tries both French and English and uses whichever validates.
 *
 * Unicode accents (e.g. é as NFC U+00E9 or NFD U+0065+U+0301) are not a problem:
 * @scure/bip39 normalizes to NFKD internally as required by the BIP-39 spec.
 */
export function mnemonicToKey(mnemonic: string, language?: MnemonicLanguage): Uint8Array {
  const normalized = mnemonic.trim().toLowerCase();
  const words = normalized.split(/\s+/);

  if (words.length !== 24) {
    throw new VaultError(VaultErrorCode.INVALID_MNEMONIC, `Expected 24 words, got ${words.length}`);
  }

  if (language) {
    const wordlist = getWordlist(language);

    if (!validateMnemonic(normalized, wordlist)) {
      throw new VaultError(VaultErrorCode.INVALID_MNEMONIC, 'Invalid mnemonic: checksum mismatch or unknown words');
    }

    return mnemonicToEntropy(normalized, wordlist);
  }

  // Try both languages — validate with each and use the one that passes
  for (const lang of ['french', 'english'] as MnemonicLanguage[]) {
    const wordlist = getWordlist(lang);

    if (validateMnemonic(normalized, wordlist)) {
      return mnemonicToEntropy(normalized, wordlist);
    }
  }

  throw new VaultError(VaultErrorCode.INVALID_MNEMONIC, 'Invalid mnemonic: checksum mismatch or unknown words');
}

/**
 * Detect which language a mnemonic is in.
 * Returns the detected language, or null if the mnemonic is invalid in both languages.
 */
export function detectMnemonicLanguage(mnemonic: string): MnemonicLanguage | null {
  const normalized = mnemonic.trim().toLowerCase();

  if (validateMnemonic(normalized, french)) return 'french';
  if (validateMnemonic(normalized, english)) return 'english';

  return null;
}
