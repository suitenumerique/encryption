import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { defineConfig } from 'vite';

const configDir = import.meta.dirname;

export default defineConfig(() => {
  // In dev, DEMO_PORT env var selects the port (default 7203)
  const port = parseInt(process.env.DEMO_PORT ?? '7201', 10);

  return {
    root: resolve(configDir),
    plugins: [react()],
    build: {
      outDir: resolve(configDir, '../../dist/demo'),
      emptyOutDir: true,
      rollupOptions: {
        input: {
          main: resolve(configDir, 'index.html'),
          benchmark: resolve(configDir, 'benchmark.html'),
        },
      },
    },
    resolve: {
      alias: {
        '@encryption': resolve(configDir, '../..'),
      },
    },
    server: {
      port,
      strictPort: true,
      proxy: {
        '/api': {
          target: 'http://localhost:7200',
          bypass(req: { url?: string }) {
            const url = req.url ?? '';
            if (url.includes('.')) return url;
          },
        },
      },
    },
    cacheDir: `../../node_modules/.vite/demo-${port}`,
  };
});
