import fastifyStatic from '@fastify/static';
import type { FastifyInstance } from 'fastify';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { env } from '@encryption/src/server/env';
import { parseBrandFont } from '@encryption/src/shared/brand-font';
import { buildRuntimeConfigBlock } from '@encryption/src/shared/runtime-config';

/**
 * Build the runtime config block injected into the interface HTML.
 */
function buildConfigBlock(): string {
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

/**
 * The `.map` files sit next to the bundles because the SERVER reads them, to resolve
 * a stack reported by a browser back to our sources (`src/server/symbolicate.ts`).
 * Nothing else needs them: the build emits them `hidden`, so no bundle references one
 * and no browser asks for one. Serving them anyway would be an accident of them
 * sharing a directory with the assets.
 */
export function isServableAsset(pathName: string): boolean {
  return !pathName.endsWith('.map');
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
    // Inject the runtime config block before </head> so it is in the DOM before any
    // module script executes and reads it.
    const configBlock = buildConfigBlock();
    interfaceHtml = rawHtml.replace('</head>', `${configBlock}\n</head>`);
  }

  // Serve static assets (JS, CSS, etc.) for the UI domain. The vendored Marianne
  // .woff for the react-pdf Recovery Kit are emitted under assets/fonts at build,
  // so they are served here too (see src/build/marianne-fonts.ts).
  app.register(fastifyStatic, {
    root: resolve(distDir, 'assets'),
    prefix: '/assets/',
    constraints: { host: env.UI_HOST },
    decorateReply: false,
    allowedPath: isServableAsset,
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
