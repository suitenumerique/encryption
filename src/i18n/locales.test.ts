import { resources } from '@encryption/src/i18n';
import commonEn from '@encryption/src/i18n/en/common.json';
import commonFr from '@encryption/src/i18n/fr/common.json';

/** Every leaf key, dotted, so two locales can be compared as flat sets. */
function leafKeys(value: unknown, prefix = ''): string[] {
  if (typeof value !== 'object' || value === null) {
    return [prefix];
  }

  return Object.entries(value).flatMap(([key, child]) => leafKeys(child, prefix ? `${prefix}.${key}` : key));
}

/**
 * i18next answers a missing key by echoing the key back, so a translation gap
 * never throws: the interface just renders "onboarding.title_enable", and a
 * Storybook play() looking for that heading fails somewhere far from the cause.
 * Comparing the two locales' key sets catches it at the source instead, and
 * needs no maintenance as the copy grows.
 */
describe('translations', () => {
  const en = leafKeys(commonEn).sort();
  const fr = leafKeys(commonFr).sort();

  it('defines the same keys in every locale', () => {
    expect(fr.filter((key) => !en.includes(key))).toEqual([]);
    expect(en.filter((key) => !fr.includes(key))).toEqual([]);
  });

  it('has no empty translation', () => {
    for (const [locale, bundle] of Object.entries(resources)) {
      const empty = leafKeys(bundle.common).filter((key) => {
        const value = key.split('.').reduce<unknown>((node, part) => (node as Record<string, unknown>)[part], bundle.common);

        return typeof value === 'string' && value.trim() === '';
      });

      expect({ locale, empty }).toEqual({ locale, empty: [] });
    }
  });
});
