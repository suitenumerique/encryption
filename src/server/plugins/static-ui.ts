import fastifyStatic from '@fastify/static';
import type { FastifyInstance } from 'fastify';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { env } from '@encryption/src/server/env';
import { parseBrandFont } from '@encryption/src/shared/brand-font';
import { buildRuntimeConfigBlock } from '@encryption/src/shared/runtime-config';

/**
 * Build the runtime config block injected into the interface HTML. It is data, not
 * script: the bundle parses and freezes it, so the tamper protection now lives in
 * SRI-pinned code rather than in an inline script no build-time hash could cover.
 */
function buildConfigScript(): string {
  const config = {
    oidcIssuer: env.OIDC_ISSUER,
    oidcClientId: env.OIDC_CLIENT_ID,
    oidcRedirectUri: env.OIDC_REDIRECT_URI,
    vaultUrl: env.VAULT_URL,
    apiBaseUrl: '', // Same origin as the UI in production
    docsEnabled: env.DOCS_ENABLED,
    brandFont: parseBrandFont(env.BRAND_FONT),
  };

  return buildRuntimeConfigBlock(config);
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

  // Serve static assets (JS, CSS, etc.) for the UI domain. The vendored Marianne
  // .woff for the react-pdf Recovery Kit are emitted under assets/fonts at build,
  // so they are served here too (see src/build/marianne-fonts.ts).
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
    if (path.startsWith('/assets/') || path.startsWith('/public-assets/') || path === '/robots.txt' || path.startsWith('/api/')) {
      return;
    }

    reply.type('text/html').send(interfaceHtml);
  });
}
