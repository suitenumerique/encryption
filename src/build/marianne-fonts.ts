import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import type { Plugin } from 'vite';

// react-pdf needs the raw Marianne .woff files (it cannot read woff2), and they
// are already shipped by @gouvfr-lasuite/ui-kit. Rather than commit the binaries
// (which git cannot diff), we treat them as ordinary build assets: emitted under
// `/assets/fonts/*` at build (so production serves them through the existing
// `/assets` static route, with no committed file and nothing to gitignore) and
// served straight from the dependency in dev/Storybook. The package only exports
// the @font-face CSS, so resolve THAT and read the .woff files next to it.
// Regular is the fallback for any unmatched weight (see pdf-fonts.ts).
export const MARIANNE_WOFF = ['Marianne-Regular.woff', 'Marianne-Medium.woff', 'Marianne-Bold.woff'];

// The URL prefix react-pdf fetches from; must match pdf-fonts.ts.
const FONTS_URL_PREFIX = '/assets/fonts/';

function marianneFontsDir(): string {
  const require = createRequire(import.meta.url);

  return dirname(require.resolve('@gouvfr-lasuite/ui-kit/fonts/Marianne'));
}

/** Serve (dev) and emit (build) the three Marianne .woff files under `/assets/fonts/`. */
export function vendorMarianneFonts(): Plugin {
  const dir = marianneFontsDir();
  const read = (file: string): Buffer => readFileSync(resolve(dir, file));

  return {
    name: 'vendor-marianne-fonts',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const path = req.url?.split('?')[0] ?? '';
        const file = path.startsWith(FONTS_URL_PREFIX) ? path.slice(FONTS_URL_PREFIX.length) : '';

        if (MARIANNE_WOFF.includes(file)) {
          res.setHeader('Content-Type', 'font/woff');
          res.end(read(file));

          return;
        }

        next();
      });
    },
    generateBundle() {
      for (const file of MARIANNE_WOFF) {
        this.emitFile({ type: 'asset', fileName: `assets/fonts/${file}`, source: read(file) });
      }
    },
  };
}
