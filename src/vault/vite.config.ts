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
 * The vault host serves a fixed allowlist of files, and the Service Worker is a
 * classic script. Both break silently if this build ever emits a third chunk: Rollup
 * does that as soon as `index.ts` and `sw.ts` import a common module, hoisting it
 * (and everything reachable from it) into a shared file that is never served.
 * Failing the build is the only place this can be caught before production.
 */
function assertOnlyExpectedChunks(): Plugin {
  return {
    name: 'vault-only-expected-chunks',
    apply: 'build',
    generateBundle(_options, bundle) {
      const chunks = Object.values(bundle)
        .filter((output) => output.type === 'chunk')
        .map((chunk) => chunk.fileName)
        .sort();
      const expected = ['sw.js', 'vault.js'];

      if (chunks.join() !== expected.join()) {
        throw new Error(
          `The vault build must emit exactly ${expected.join(', ')}; got ${chunks.join(', ')}. Did sw.ts and index.ts start sharing a module?`
        );
      }
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
      assertOnlyExpectedChunks(),
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
      sourcemap: 'hidden', // Disable `sourceMappingURL` comment since `.map` files are not served by the backend
      rollupOptions: {
        input: {
          main: resolve(configDir, 'bridge.html'),
          sw: resolve(configDir, 'sw.ts'),
        },
        output: {
          sourcemapExcludeSources: true, // Make `.map` files containing only positions, not the original code (since it's public already)
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

export default defineConfig(async ({ command }) => {
  const { default: sri } = await import('vite-plugin-sri-gen');
  const config = getVaultViteConfig();

  // Only needed when developping so files are served
  if (command === 'build') {
    config.publicDir = false;
  }

  config.plugins = [sri({ algorithm: 'sha384' }), ...(config.plugins ?? [])];

  return config;
});
