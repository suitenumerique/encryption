import { appendFileSync } from 'fs';
import { resolve } from 'path';
import sbom from 'rollup-plugin-sbom';
import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';

const configDir = import.meta.dirname;

export default defineConfig({
  build: {
    outDir: resolve(configDir, '../../dist/client'),
    emptyOutDir: true,
    lib: {
      entry: resolve(configDir, 'index.ts'),
      name: 'EncryptionClient',
      formats: ['es', 'iife'],
      fileName: (format) => (format === 'es' ? 'client.mjs' : 'client.js'),
    },
    sourcemap: 'hidden', // Disable `sourceMappingURL` comment since `.map` files are not served by the backend
    rollupOptions: {
      output: { sourcemapExcludeSources: true }, // Make `.map` files containing only positions, not the original code (since it's public already)
    },
  },
  resolve: {
    alias: {
      '@encryption': resolve(configDir, '../..'),
    },
  },
  plugins: [
    {
      ...sbom({
        outDir: '.',
        outFilename: 'sbom.cdx',
        includeWellKnown: false,
      }),
      apply: (config) => !config.build?.watch, // An SBOM is a release artifact, so skip it under `vite build --watch`
    },
    // Generate a single self-contained client.d.ts from the TypeScript source
    // (VaultClient + shared/vault-error), so the public type contract can never
    // drift from the implementation. Emitted into dist/client, never committed.
    dts({
      bundleTypes: true,
      tsconfigPath: resolve(configDir, '../../tsconfig.json'),
      // The SDK only depends on src/client + src/shared; scoping the declaration
      // pass to those (and dropping tests/stories) keeps it off unrelated files.
      include: ['src/client/**/*.ts', 'src/shared/**/*.ts'],
      exclude: ['**/*.test.ts', '**/*.test.tsx', '**/*.stories.ts', '**/*.stories.tsx'],
      // api-extractor strips `declare global` / UMD globals, so append the UMD
      // namespace declaration that types the <script>-tag `EncryptionClient`
      // global (products loading client.js get `EncryptionClient.VaultClient`).
      afterBuild: () => {
        appendFileSync(resolve(configDir, '../../dist/client/client.d.mts'), '\nexport as namespace EncryptionClient;\n');
      },
    }),
  ],
});
