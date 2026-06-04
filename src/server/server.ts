import Fastify from 'fastify';

import { jwtAuthPlugin } from '@encryption/src/server/plugins/jwt-auth';
import { securityHeadersPlugin } from '@encryption/src/server/plugins/security-headers';
import { deviceTransferRoute } from '@encryption/src/server/routes/device-transfer';
import { publicKeysRoute } from '@encryption/src/server/routes/public-keys';
import { versionRoute } from '@encryption/src/server/routes/versions';

const isDev = process.env.NODE_ENV === 'development';

export async function createServer() {
  const app = Fastify({
    logger: {
      level: isDev ? 'debug' : 'info',
    },
  });

  // Register plugins
  app.register(securityHeadersPlugin);
  app.register(jwtAuthPlugin);

  if (isDev) {
    // In development, embed Vite dev servers as middleware (vault + UI)
    const { viteDevPlugin } = await import('@encryption/src/server/plugins/vite-dev');
    app.register(viteDevPlugin);
  } else {
    // In production, serve pre-built static files
    const { staticVaultPlugin } = await import('@encryption/src/server/plugins/static-vault');
    const { staticUiPlugin } = await import('@encryption/src/server/plugins/static-ui');
    app.register(staticVaultPlugin);
    app.register(staticUiPlugin);
  }

  // Register routes
  app.register(versionRoute);
  app.register(publicKeysRoute);
  app.register(deviceTransferRoute);

  // Health check
  app.get('/health', async () => {
    return { status: 'ok' };
  });

  // Prevent indexing on both domains
  app.get('/robots.txt', async (_, reply) => {
    reply.type('text/plain').send('User-agent: *\nDisallow: /\n');
  });

  return app;
}
