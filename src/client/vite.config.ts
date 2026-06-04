import { resolve } from 'path';
import { defineConfig } from 'vite';

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
});
