import mdx from '@mdx-js/rollup';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import remarkGfm from 'remark-gfm';
import sbom from 'rollup-plugin-sbom';
import { type Plugin, type UserConfig, defineConfig } from 'vite';

import { getMinBrowserVersions } from '../build/generate-min-browser-versions.ts';
import { vendorMarianneFonts } from '../build/marianne-fonts.ts';
import { parseBrandFont } from '../shared/brand-font.ts';
import { buildRuntimeConfigBlock } from '../shared/runtime-config.ts';

const configDir = import.meta.dirname;

/**
 * Inject the runtime config data block into the HTML in dev mode,
 * mimicking what the Fastify server does in production.
 */
function injectRuntimeConfig(): Plugin {
  return {
    name: 'inject-encryption-config',
    apply: 'serve', // Without it it would bake one in at build time and would leave the document with two (reading the first one)
    transformIndexHtml(html) {
      const config = {
        oidcIssuer: process.env.OIDC_ISSUER,
        oidcClientId: process.env.OIDC_CLIENT_ID,
        oidcRedirectUri: process.env.OIDC_REDIRECT_URI,
        vaultUrl: process.env.VAULT_URL,
        apiBaseUrl: '',
        docsEnabled: process.env.DOCS_ENABLED !== 'false',
        brandFont: parseBrandFont(process.env.BRAND_FONT),
      };
      const block = buildRuntimeConfigBlock(config);

      return html.replace('</head>', `${block}\n</head>`);
    },
  };
}

/**
 * SPA fallback for interface.html in dev mode.
 * Vite's built-in SPA fallback only works with index.html, but our entry
 * is interface.html. This plugin serves it for all non-asset HTML routes
 * (e.g. /onboarding, /settings).
 */
function spaFallback(): Plugin {
  return {
    name: 'spa-fallback-interface',
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        const url = req.url?.split('?')[0] ?? '';

        // Rewrite SPA routes to interface.html. Skip:
        // - Vite internal paths (/@...)
        // - Asset paths (/assets/...)
        // - API paths (/api/...) — handled by Fastify routes
        // - Files with extensions (.ts, .js, .css, etc.)
        if (!url.startsWith('/@') && !url.startsWith('/assets/') && !url.startsWith('/api/') && !url.includes('.')) {
          req.url = '/interface.html';
        }

        next();
      });
    },
  };
}

/**
 * Shared Vite config for the UI.
 * Used both by `vite build` and by the Fastify vite-dev plugin in dev mode.
 */
export function getUiViteConfig(): UserConfig {
  const minBrowserVersions = getMinBrowserVersions();

  return {
    root: resolve(configDir),
    plugins: [
      {
        ...sbom({
          outDir: '.',
          outFilename: 'sbom.cdx',
          includeWellKnown: false,
        }),
        apply: 'build' as const, // SBOM is meaningless in dev mode
      },
      mdx({
        providerImportSource: '@mdx-js/react',
        remarkPlugins: [remarkGfm],
      }),
      react(),
      spaFallback(),
      injectRuntimeConfig(),
      vendorMarianneFonts(),
    ],
    define: {
      __MIN_BROWSER_VERSIONS__: JSON.stringify(minBrowserVersions),
    },
    build: {
      outDir: resolve(configDir, '../../dist/ui'),
      emptyOutDir: true,
      rollupOptions: {
        input: resolve(configDir, 'interface.html'),
      },
    },
    resolve: {
      alias: {
        '@encryption': resolve(configDir, '../..'),
      },
    },
    cacheDir: resolve(configDir, '../../node_modules/.vite/ui'),
  };
}

export default defineConfig(async () => {
  const { default: sri } = await import('vite-plugin-sri-gen');
  const config = getUiViteConfig();

  config.plugins = [...(config.plugins ?? []), sri({ algorithm: 'sha384' })];

  return config;
});
