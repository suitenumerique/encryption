import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { defineConfig } from 'vite';

export default defineConfig(() => {
  // In dev, DEMO_PORT env var selects the port (default 7203)
  const port = parseInt(process.env.DEMO_PORT ?? '7201', 10);

  return {
    root: resolve(__dirname),
    plugins: [react()],
    build: {
      outDir: resolve(__dirname, '../../dist/demo'),
      emptyOutDir: true,
      rollupOptions: {
        input: {
          main: resolve(__dirname, 'index.html'),
          benchmark: resolve(__dirname, 'benchmark.html'),
        },
      },
    },
    resolve: {
      alias: {
        '@encryption': resolve(__dirname, '../..'),
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
