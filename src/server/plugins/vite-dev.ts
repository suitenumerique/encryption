import middie from '@fastify/middie';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import type { IncomingMessage } from 'node:http';
import { resolve } from 'node:path';

import { env } from '@encryption/src/server/env';

/**
 * Development-only plugin that embeds Vault and UI Vite dev servers
 * as middleware inside Fastify, replacing the separate Vite processes.
 *
 * Requests are dispatched by hostname:
 * - VAULT_HOST (e.g. data.encryption.local:7200) → vault Vite middleware
 * - UI_HOST (e.g. encryption.local:7200) → UI Vite middleware
 * - Other hosts → fall through to Fastify routes (API, health, etc.)
 *
 * Each Vite instance gets its own HMR WebSocket path to avoid conflicts
 * on the shared HTTP server.
 *
 * Wrapped with fastify-plugin to break encapsulation — the middleware
 * must apply at the root scope so it intercepts requests before Fastify routes.
 */
export const viteDevPlugin = fp(async (app: FastifyInstance): Promise<void> => {
  const { createServer: createViteServer } = await import('vite');

  const httpServer = app.server;
  const root = resolve(__dirname, '../../..');

  // Create Vault Vite dev server in middleware mode.
  // Use configFile so Vite resolves the config natively (avoids tsx ESM issues).
  const vaultVite = await createViteServer({
    configFile: resolve(root, 'src/vault/vite.config.ts'),
    server: {
      middlewareMode: true,
      allowedHosts: [new URL(env.VAULT_URL).hostname],
      hmr: {
        server: httpServer,
        path: '/__vite_hmr_vault',
      },
    },
    appType: 'spa',
  });

  // Create UI Vite dev server in middleware mode
  const uiVite = await createViteServer({
    configFile: resolve(root, 'src/ui/vite.config.ts'),
    server: {
      middlewareMode: true,
      allowedHosts: [new URL(env.UI_URL).hostname],
      hmr: {
        server: httpServer,
        path: '/__vite_hmr_ui',
      },
    },
    appType: 'spa',
  });

  // Register Connect middleware support
  await app.register(middie);

  // Route requests to the correct Vite middleware based on hostname.
  // API and infrastructure routes always go to Fastify.
  app.use((req: IncomingMessage, res, next) => {
    const host = req.headers.host ?? '';
    const url = req.url ?? '';
    const path = url.split('?')[0];

    // Let Fastify handle infrastructure routes and API calls.
    // Paths with file extensions under /api/ (e.g. /api/server-client.ts)
    // are Vite source files that must be served by the Vite middleware.
    const isApiRoute = path.startsWith('/api/') && !path.slice(path.lastIndexOf('/') + 1).includes('.');
    if (path === '/health' || path === '/robots.txt' || isApiRoute) {
      return next();
    }

    if (host === env.VAULT_HOST) {
      vaultVite.middlewares(req, res, next);
    } else if (host === env.UI_HOST) {
      uiVite.middlewares(req, res, next);
    } else {
      next();
    }
  });

  // Clean up Vite servers when Fastify shuts down
  app.addHook('onClose', async () => {
    await vaultVite.close();
    await uiVite.close();
  });

  app.log.info(`Vault dev server attached for host: ${env.VAULT_HOST}`);
  app.log.info(`UI dev server attached for host: ${env.UI_HOST}`);
});
