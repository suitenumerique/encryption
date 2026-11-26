import { storybookTest } from '@storybook/addon-vitest/vitest-plugin';
import { playwright } from '@vitest/browser-playwright';
import { resolve } from 'path';
import { defineConfig } from 'vitest/config';

const configDir = import.meta.dirname;

export default defineConfig({
  plugins: [
    storybookTest({
      configDir: resolve(configDir, '.storybook'),
      disableAddonDocs: false, // `false` otherwise mdx won't load into story tests when there are
    }),
  ],
  resolve: {
    alias: {
      '@encryption': resolve(configDir, '.'),
    },
  },
  test: {
    name: 'storybook',
    browser: {
      enabled: true,
      provider: playwright(),
      instances: [{ browser: 'chromium' }],
    },
    setupFiles: ['./vitest.storybook-setup.ts'],
  },
});
