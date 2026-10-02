import { resolve } from 'path';
import { defineConfig } from 'vitest/config';

const configDir = import.meta.dirname;

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
