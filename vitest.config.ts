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
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
    environment: 'node', // Node by default, opt-in needed for DOM tests
    globalSetup: ['./vitest.global-setup.ts'],
    coverage: {
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.d.ts', 'src/**/*.test.{ts,tsx}', 'src/**/index.ts'],
    },
  },
});
