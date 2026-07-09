import fastifyStatic from '@fastify/static';
import type { FastifyInstance } from 'fastify';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { env } from '@encryption/src/server/env';

/**
 * Build the runtime config script that is injected into the interface HTML.
 * Uses Object.defineProperty with writable:false + configurable:false
 * so a malicious library cannot overwrite the values.
 */
function buildConfigScript(): string {
  const config = {
    oidcIssuer: env.OIDC_ISSUER,
    oidcClientId: env.OIDC_CLIENT_ID,
    oidcRedirectUri: env.OIDC_REDIRECT_URI,
    vaultUrl: env.VAULT_URL,
    apiBaseUrl: '', // Same origin as the UI in production
    docsEnabled: env.DOCS_ENABLED,
  };

  return `<script>Object.defineProperty(window,"__ENCRYPTION_CONFIG__",{value:Object.freeze(${JSON.stringify(config)}),writable:false,enumerable:true,configurable:false});</script>`;
}

export async function staticUiPlugin(app: FastifyInstance): Promise<void> {
  const distDir = resolve(process.cwd(), 'dist/ui');

  if (!existsSync(distDir)) {
    app.log.warn('UI dist files not found - run "npm run build:ui" first');

    return;
  }

  const htmlPath = resolve(distDir, 'interface.html');
  let interfaceHtml: string | null = null;

  if (existsSync(htmlPath)) {
    const rawHtml = readFileSync(htmlPath, 'utf-8');
    // Inject the runtime config script before </head> so it's available
    // before any module script executes.
    const configScript = buildConfigScript();
    interfaceHtml = rawHtml.replace('</head>', `${configScript}\n</head>`);
  }

  // Serve static assets (JS, CSS, etc.) for the UI domain
  app.register(fastifyStatic, {
    root: resolve(distDir, 'assets'),
    prefix: '/assets/',
    constraints: { host: env.UI_HOST },
    decorateReply: false,
  });

  // Serve interface.html for all HTML routes (SPA fallback)
  app.addHook('onRequest', async (request, reply) => {
    // `request.host` keeps the port, matching env.UI_HOST (derived from new URL(...).host).
    // The port-stripped `request.hostname` would never match on a deployment with an explicit port.
    if (request.host !== env.UI_HOST || !interfaceHtml) {
      return;
    }

    const path = request.url.split('?')[0];

    // Skip asset and API requests
    if (path.startsWith('/assets/') || path === '/robots.txt' || path.startsWith('/api/')) {
      return;
    }

    reply.type('text/html').send(interfaceHtml);
  });
}
