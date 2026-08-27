import { resolve } from 'path';
import { type Plugin, type UserConfig, defineConfig } from 'vite';

/**
 * Inject __ENCRYPTION_VAULT_CONFIG__ into bridge.html in dev mode,
 * mimicking what the Fastify server does in production.
 */
function injectRuntimeConfig(): Plugin {
  return {
    name: 'inject-vault-config',
    transformIndexHtml(html) {
      const config = {
        allowedOrigins: (process.env.ALLOWED_FRAME_ANCESTORS ?? '')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        interfaceOrigin: process.env.UI_URL ?? '',
      };
      const script = `<script>Object.defineProperty(window,"__ENCRYPTION_VAULT_CONFIG__",{value:Object.freeze(${JSON.stringify(config)}),writable:false,enumerable:true,configurable:false});</script>`;

      return html.replace('</head>', `${script}\n</head>`);
    },
  };
}

/**
 * Shared Vite config for the vault.
 * Used both by `vite build` and by the Fastify vite-dev plugin in dev mode.
 */
export function getVaultViteConfig(): UserConfig {
  return {
    root: resolve(__dirname),
    plugins: [injectRuntimeConfig()],
    build: {
      outDir: resolve(__dirname, '../../dist/vault'),
      emptyOutDir: true,
      // `hidden`, not `true`: the .map is emitted next to the bundle but NO
      // `sourceMappingURL` comment is appended, so the shipped bytes are unchanged
      // (SRI hashes stay stable) and no browser ever fetches it. The map is read
      // only by our own server, to resolve a reported stack back to source.
      sourcemap: 'hidden',
      rollupOptions: {
        input: {
          main: resolve(__dirname, 'bridge.html'),
          sw: resolve(__dirname, 'sw.ts'),
        },
        output: {
          // Positions only, no source text: see the interface config.
          sourcemapExcludeSources: true,
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
        '@encryption': resolve(__dirname, '../..'),
      },
    },
    // In dev mode, serve the built client SDK files (client.js, client.mjs, client.d.ts)
    // from dist/client/ so products can load them via <script> tag.
    // Run `npm run build:client` first, or `npm run build` to generate these files.
    publicDir: resolve(__dirname, '../../dist/client'),
    cacheDir: resolve(__dirname, '../../node_modules/.vite/vault'),
  };
}

export default defineConfig(async ({ command }) => {
  const { default: sri } = await import('vite-plugin-sri-gen');
  const config = getVaultViteConfig();

  // `publicDir` above exists to serve the SDK on the vault host in DEV. On a build it
  // would instead copy dist/client into dist/vault, where nothing reads it: the
  // server's vault allowlist serves the SDK out of dist/client. Worse, build:client
  // and build:vault run concurrently, so what got copied was whatever the previous
  // build had left in dist/client, and the image carried a stale duplicate of the SDK
  // with its maps.
  if (command === 'build') {
    config.publicDir = false;
  }

  config.plugins = [sri({ algorithm: 'sha384' }), ...(config.plugins ?? [])];

  return config;
});
