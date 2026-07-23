import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { z } from 'zod';

import { configureZodValidation } from '@encryption/src/server/zod-validation';

/**
 * Compute a single build version hash from all distributed bundles.
 * This is computed once at server startup.
 *
 * Set the `VERSION_SALT` env var to force a cache bust without rebuilding
 * the Docker image. This is useful when external state has changed (e.g. JWKS
 * key rotation) and you need the Service Worker to invalidate its cache
 * and refetch everything — just redeploy with a new salt value.
 *
 * Example: VERSION_SALT=jwks-rotated-2026-03-19
 */
function computeBuildVersion(): string {
  const hash = createHash('sha256');
  const distDir = resolve(process.cwd(), 'dist');

  const files = ['server/main.mjs', 'vault/vault.js', 'vault/bridge.html', 'ui/interface.html', 'client/client.js'];

  for (const file of files) {
    const filePath = resolve(distDir, file);

    if (existsSync(filePath)) {
      hash.update(readFileSync(filePath));
    }
  }

  if (process.env.VERSION_SALT) {
    hash.update(process.env.VERSION_SALT);
  }

  return hash.digest('hex').slice(0, 12);
}

export async function versionRoute(app: FastifyInstance): Promise<void> {
  configureZodValidation(app);

  const version = computeBuildVersion();

  app.withTypeProvider<ZodTypeProvider>().get('/api/version', {
    schema: {
      response: {
        200: z.object({ version: z.string() }),
      },
    },
    handler: async () => {
      return { version };
    },
  });
}
