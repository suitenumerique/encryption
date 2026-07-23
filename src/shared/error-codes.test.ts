import commonEn from '@encryption/src/i18n/en/common.json';
import commonFr from '@encryption/src/i18n/fr/common.json';
import * as errorCodes from '@encryption/src/shared/error-codes';

const CODES: string[] = Object.values(errorCodes).filter((value) => typeof value === 'string');

const LOCALES = {
  en: commonEn.errors.api as Record<string, string>,
  fr: commonFr.errors.api as Record<string, string>,
};

/**
 * The server sends a stable `code`; the text lives in the shared i18n files and
 * is read from BOTH ends (the interface translates it, and the server attaches
 * the English one to every error body via attachApiErrorMessages). A code with
 * no entry silently degrades: i18next echoes the key back, so the UI shows
 * "errors.api.vault_manifest_invalid" or falls through to a generic message.
 */
describe('API error codes', () => {
  it.each(Object.keys(LOCALES))('has a translation for every code in %s', (locale) => {
    const missing = CODES.filter((code) => !LOCALES[locale as keyof typeof LOCALES][code]);

    expect(missing).toEqual([]);
  });

  it.each(Object.keys(LOCALES))('has no orphan translation in %s pointing at a removed code', (locale) => {
    const orphans = Object.keys(LOCALES[locale as keyof typeof LOCALES]).filter((key) => !CODES.includes(key));

    expect(orphans).toEqual([]);
  });

  it('keeps the two locales genuinely distinct, so a copy-paste cannot pass as a translation', () => {
    const identical = CODES.filter((code) => LOCALES.en[code] === LOCALES.fr[code]);

    expect(identical).toEqual([]);
  });
});
