import fastifyStatic from '@fastify/static';
import type { FastifyInstance } from 'fastify';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Assets that are fetched from OUTSIDE a browser tab on our origin: the logo
 * embedded in notification emails (loaded by a mail client) and the fonts a
 * generated PDF pulls in. They are served cross-origin (the CORP exception lives
 * in security-headers) with a long cache, unlike the rest of the interface which
 * is same-site and iframe-only.
 */
export async function publicAssetsPlugin(app: FastifyInstance): Promise<void> {
  const root = resolve(process.cwd(), 'src/server/public-assets');

  if (!existsSync(root)) {
    app.log.warn('public-assets directory not found');

    return;
  }

  await app.register(fastifyStatic, {
    root,
    prefix: '/public-assets/',
    decorateReply: false,
    cacheControl: true,
    maxAge: '7d',
  });
}
