import mdx from '@mdx-js/rollup';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { type Plugin, type UserConfig, defineConfig } from 'vite';

import { getMinBrowserVersions } from '../build/generate-min-browser-versions';

/**
 * Inject __ENCRYPTION_CONFIG__ into the HTML in dev mode,
 * mimicking what the Fastify server does in production.
 */
function injectRuntimeConfig(): Plugin {
  return {
    name: 'inject-encryption-config',
    transformIndexHtml(html) {
      const config = {
        oidcIssuer: process.env.OIDC_ISSUER,
        oidcClientId: process.env.OIDC_CLIENT_ID,
        oidcRedirectUri: process.env.OIDC_REDIRECT_URI,
        vaultUrl: process.env.VAULT_URL,
        apiBaseUrl: '',
        docsEnabled: process.env.DOCS_ENABLED !== 'false',
      };
      const script = `<script>Object.defineProperty(window,"__ENCRYPTION_CONFIG__",{value:Object.freeze(${JSON.stringify(config)}),writable:false,enumerable:true,configurable:false});</script>`;

      return html.replace('</head>', `${script}\n</head>`);
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
    root: resolve(__dirname),
    plugins: [
      mdx({
        providerImportSource: '@mdx-js/react',
      }),
      react(),
      spaFallback(),
      injectRuntimeConfig(),
    ],
    define: {
      __MIN_BROWSER_VERSIONS__: JSON.stringify(minBrowserVersions),
    },
    build: {
      outDir: resolve(__dirname, '../../dist/ui'),
      emptyOutDir: true,
      rollupOptions: {
        input: resolve(__dirname, 'interface.html'),
      },
    },
    resolve: {
      alias: {
        '@encryption': resolve(__dirname, '../..'),
      },
    },
    cacheDir: resolve(__dirname, '../../node_modules/.vite/ui'),
  };
}

export default defineConfig(async () => {
  const { default: sri } = await import('vite-plugin-sri-gen');
  const config = getUiViteConfig();

  config.plugins = [...(config.plugins ?? []), sri({ algorithm: 'sha384' })];

  return config;
});
