import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { type Plugin, defineConfig } from 'vite';

import { inlineIntoHtml } from './single-file.ts';

const configDir = import.meta.dirname;

/**
 * Folds the bundle into the HTML page and drops the separate files, so the build
 * output is the one file operators carry to an isolated computer and open from
 * disk (see single-file.ts for the policy it gets).
 */
/** In development, the server root opens the tool, which is the only page there is. */
function openToolAtRoot(): Plugin {
  return {
    name: 'maintenance-tool-root',
    apply: 'serve',
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        if (request.url !== '/') return next();

        response.statusCode = 302;
        response.setHeader('Location', '/maintenance-tool.html');
        response.end();
      });
    },
  };
}

function singleFile(): Plugin {
  return {
    name: 'maintenance-tool-single-file',
    apply: 'build',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const outputs = Object.values(bundle);
      const html = outputs.find((output) => output.type === 'asset' && output.fileName.endsWith('.html'));
      const chunks = outputs.filter((output) => output.type === 'chunk');
      const styles = outputs.filter((output) => output.type === 'asset' && output.fileName.endsWith('.css'));

      if (!html || html.type !== 'asset' || chunks.length !== 1 || chunks[0].type !== 'chunk' || styles.length > 1) {
        throw new Error(
          `The maintenance tool must build to one page, one script and at most one stylesheet; got ${outputs.map((o) => o.fileName).join(', ')}`
        );
      }

      const style = styles[0]?.type === 'asset' ? String(styles[0].source) : '';

      html.source = inlineIntoHtml(String(html.source), chunks[0].code, style);

      for (const output of [...chunks, ...styles]) delete bundle[output.fileName];
    },
  };
}

export default defineConfig({
  root: configDir,
  // Relative URLs: the page is opened from a file, never served from a root.
  base: './',
  plugins: [react(), singleFile(), openToolAtRoot()],
  // `npm run dev:maintenance`: the tool with hot reload while working on it. Served,
  // so without the policy the build folds in; the built file is what operators get.
  server: {
    // Every interface, as Storybook listens: a development VM forwards to the host
    // the ports bound on all of them, not those bound on its loopback alone.
    host: true,
    port: 7210,
    strictPort: true,
    open: false,
  },
  build: {
    outDir: resolve(configDir, '../../../dist/maintenance'),
    emptyOutDir: true,
    sourcemap: false,
    modulePreload: false,
    cssCodeSplit: false,
    assetsInlineLimit: Number.MAX_SAFE_INTEGER,
    rollupOptions: {
      input: resolve(configDir, 'maintenance-tool.html'),
      output: { codeSplitting: false },
    },
  },
  resolve: {
    alias: {
      '@encryption': resolve(configDir, '../../..'),
    },
  },
  cacheDir: resolve(configDir, '../../../node_modules/.vite/maintenance-tool'),
});
