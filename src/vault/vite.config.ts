import { resolve } from 'path';
import sbom from 'rollup-plugin-sbom';
import { type Plugin, type UserConfig, defineConfig } from 'vite';

import { buildRuntimeConfigBlock } from '../shared/runtime-config.ts';

const configDir = import.meta.dirname;

/**
 * Inject the runtime config data block into bridge.html in dev mode,
 * mimicking what the Fastify server does in production.
 */
function injectRuntimeConfig(): Plugin {
  return {
    name: 'inject-vault-config',
    apply: 'serve', // Without it it would bake one in at build time and would leave the document with two (reading the first one)
    transformIndexHtml(html) {
      const config = {
        allowedOrigins: (process.env.ALLOWED_FRAME_ANCESTORS ?? '')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        interfaceOrigin: process.env.UI_URL ?? '',
      };
      const block = buildRuntimeConfigBlock(config);

      return html.replace('</head>', `${block}\n</head>`);
    },
  };
}

/**
 * Shared Vite config for the vault.
 * Used both by `vite build` and by the Fastify vite-dev plugin in dev mode.
 */
export function getVaultViteConfig(): UserConfig {
  return {
    root: resolve(configDir),
    plugins: [
      injectRuntimeConfig(),
      {
        ...sbom({
          outDir: '.',
          outFilename: 'sbom.cdx',
          includeWellKnown: false,
        }),
        apply: 'build' as const, // SBOM is meaningless in dev mode
      },
    ],
    build: {
      outDir: resolve(configDir, '../../dist/vault'),
      emptyOutDir: true,
      rollupOptions: {
        input: {
          main: resolve(configDir, 'bridge.html'),
          sw: resolve(configDir, 'sw.ts'),
        },
        output: {
          manualChunks: undefined,
          inlineDynamicImports: false,
          entryFileNames: (chunkInfo: { name: string }) => {
            return chunkInfo.name === 'sw' ? 'sw.js' : 'vault.js';
          },
          assetFileNames: '[name][extname]',
        },
      },
      cssCodeSplit: false,
    },
    resolve: {
      alias: {
        '@encryption': resolve(configDir, '../..'),
      },
    },
    // In dev mode, serve the built client SDK files (client.js, client.mjs, client.d.ts)
    // from dist/client/ so products can load them via <script> tag.
    // Run `npm run build:client` first, or `npm run build` to generate these files.
    publicDir: resolve(configDir, '../../dist/client'),
    cacheDir: resolve(configDir, '../../node_modules/.vite/vault'),
  };
}

export default defineConfig(async () => {
  const { default: sri } = await import('vite-plugin-sri-gen');
  const config = getVaultViteConfig();

  config.plugins = [sri({ algorithm: 'sha384' }), ...(config.plugins ?? [])];

  return config;
});
