import { appendFileSync } from 'fs';
import { resolve } from 'path';
import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';

export default defineConfig({
  build: {
    outDir: resolve(__dirname, '../../dist/client'),
    emptyOutDir: true,
    lib: {
      entry: resolve(__dirname, 'index.ts'),
      name: 'EncryptionClient',
      formats: ['es', 'iife'],
      fileName: (format) => (format === 'es' ? 'client.mjs' : 'client.js'),
    },
    sourcemap: true,
  },
  resolve: {
    alias: {
      '@encryption': resolve(__dirname, '../..'),
    },
  },
  plugins: [
    // Generate a single self-contained client.d.ts from the TypeScript source
    // (VaultClient + shared/vault-error), so the public type contract can never
    // drift from the implementation. Emitted into dist/client, never committed.
    dts({
      rollupTypes: true,
      tsconfigPath: resolve(__dirname, '../../tsconfig.json'),
      // The SDK only depends on src/client + src/shared; scoping the declaration
      // pass to those (and dropping tests/stories) keeps it off unrelated files.
      include: ['src/client/**/*.ts', 'src/shared/**/*.ts'],
      exclude: ['**/*.test.ts', '**/*.test.tsx', '**/*.stories.ts', '**/*.stories.tsx'],
      // api-extractor strips `declare global` / UMD globals, so append the UMD
      // namespace declaration that types the <script>-tag `EncryptionClient`
      // global (products loading client.js get `EncryptionClient.VaultClient`).
      afterBuild: () => {
        appendFileSync(resolve(__dirname, '../../dist/client/client.d.mts'), '\nexport as namespace EncryptionClient;\n');
      },
    }),
  ],
});
