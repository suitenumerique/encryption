import { createInstance } from 'i18next';

import { defaultNamespace, i18nFormat, resources } from '@encryption/src/i18n';

/**
 * Server-side i18next instance, sharing the SAME translation files as the
 * interface (src/i18n/{en,fr}/common.json). It exists so error messages are not
 * duplicated in a second hand-maintained map: `errors.api.{code}` is written
 * once and read by both ends.
 *
 * Separate instance rather than the app's default one because that one is
 * browser-shaped: it installs LanguageDetector (needs `window`) and
 * initReactI18next. Here the language is fixed, so neither applies.
 *
 * English on purpose: this text is for consumers that are NOT a translated UI
 * (logs, the client SDK, product backends). A UI translates the `code` itself
 * and only falls back to this when it has no translation for it.
 */
const serverI18n = createInstance();

void serverI18n.init({
  resources,
  defaultNS: defaultNamespace,
  lng: 'en',
  fallbackLng: 'en',
  interpolation: { escapeValue: false, format: i18nFormat },
});

/**
 * Translate a key for a recipient whose language is fixed (emails/documents), so
 * the locale is passed per call rather than being ambient. `t` is for text
 * rendered as-is; `tHtml` escapes interpolated values so a translation may carry
 * inline markup (e.g. <strong>) rendered through dangerouslySetInnerHTML.
 */
export function t(locale: string, key: string, params?: Record<string, unknown>): string {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return serverI18n.t(key as any, { lng: locale, ...params }) as string;
}

export function tHtml(locale: string, key: string, params?: Record<string, unknown>): string {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return serverI18n.t(key as any, { lng: locale, ...params, interpolation: { escapeValue: true } }) as string;
}

/**
 * The English sentence for an API error code, or undefined when the code has no
 * translation (i18next returns the key itself, which is worse than nothing on
 * the wire). `params` feeds the `{{placeholders}}` a few codes use.
 */
export function apiErrorMessage(code: string, params?: Record<string, unknown>): string | undefined {
  const key = `errors.api.${code}` as const;
  // Cast for the same reason as translateApiError in src/i18n: the code is only
  // known at runtime, so it cannot satisfy i18next's literal-union key type.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const translated = serverI18n.t(key as any, params ?? {}) as string;

  // i18next echoes the key back when it is missing, which would be worse than
  // sending nothing at all.
  return translated === key ? undefined : translated;
}
