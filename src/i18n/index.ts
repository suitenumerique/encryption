import i18n from 'i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import { initReactI18next } from 'react-i18next';

import commonEn from '@encryption/src/i18n/en/common.json';
import commonFr from '@encryption/src/i18n/fr/common.json';

export const defaultNamespace = 'common';

export const resources = {
  en: { common: commonEn },
  fr: { common: commonFr },
} as const;

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    defaultNS: defaultNamespace,
    fallbackLng: 'fr',
    supportedLngs: ['en', 'fr'],
    interpolation: {
      escapeValue: false,
    },
    showSupportNotice: false,
    detection: {
      order: ['cookie', 'localStorage', 'navigator'],
    },
  });

export default i18n;

/**
 * Translate a server API error response.
 * The server returns { code: 'error_code', params?: {...} }.
 * This function looks up `errors.api.{code}` in the translations.
 */
export function translateApiError(error: { code?: string; params?: Record<string, unknown>; message?: string }): string {
  if (!error.code) {
    return i18n.t('errors.unknown');
  }

  const key = `errors.api.${error.code}` as const;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const translated = i18n.t(key as any, error.params ?? {});

  if (translated !== key) {
    return translated;
  }

  // i18next returns the key itself when it is missing. Prefer the server's
  // English default over a generic "unknown error": most codes are not (yet)
  // translated, and a precise English sentence beats an empty one.
  return error.message ?? i18n.t('errors.unknown');
}
