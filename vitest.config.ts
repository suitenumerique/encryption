import { resolve } from 'path';
import { defineConfig } from 'vitest/config';

const configDir = import.meta.dirname;

// Two projects in one config. `unit` is the suite that runs everywhere and needs the
// PGlite snapshot from the global setup; `helm` shells out to the helm binary to
// render the chart, so it is run on its own (`npm run test:helm`) and only where helm
// is installed. `vitest run --project <name>` selects one.
export default defineConfig({
  resolve: {
    alias: {
      '@encryption': resolve(configDir, '.'),
    },
  },
  test: {
    root: resolve(configDir),
    environment: 'node', // Node by default, opt-in needed for DOM tests
    coverage: {
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.d.ts', 'src/**/*.test.{ts,tsx}', 'src/**/index.ts'],
    },
    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
          globalSetup: ['./vitest.global-setup.ts'],
        },
      },
      {
        extends: true,
        test: {
          name: 'helm',
          include: ['deploy/helm/**/*.test.ts'],
          testTimeout: 120_000,
        },
      },
    ],
  },
});
