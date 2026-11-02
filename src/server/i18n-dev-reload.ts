import { readFileSync, watchFile } from 'node:fs';
import { resolve } from 'node:path';

import { defaultNamespace, resources } from '@encryption/src/i18n';
import { reloadTranslations } from '@encryption/src/server/i18n';

/**
 * Development only: a translation edit reloads its file in the running server
 * instead of restarting it (`tsx watch` leaves these files out), which would cut
 * every page off meanwhile. Kept apart from `i18n.ts`, which the email templates
 * also load in the browser (Storybook), where `node:fs` does not exist.
 */
export function watchTranslations(): void {
  for (const locale of Object.keys(resources)) {
    const file = resolve('src/i18n', locale, `${defaultNamespace}.json`);

    watchFile(file, { interval: 500 }, () => {
      try {
        reloadTranslations(locale, JSON.parse(readFileSync(file, 'utf8')));
      } catch {
        // A file caught mid-save: the next change reloads it.
      }
    });
  }
}
