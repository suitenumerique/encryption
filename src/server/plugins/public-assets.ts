import fastifyStatic from '@fastify/static';
import type { FastifyInstance } from 'fastify';
import { existsSync, readFileSync } from 'node:fs';
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

  // The generated VaultClient type declaration, served on every host with the
  // /public-assets cross-origin CORP exception so an integrating product can
  // fetch and vendor it without cloning this repo, building a dist, or us
  // publishing a package. Read lazily from the build output (not snapshotted at
  // boot) so a `dev:client` watch rebuild is picked up with no restart. Vite's
  // dts plugin writes `.d.mts` (the full build only cp's it to `.d.ts`); its
  // content is identical, so we serve it under the friendlier `.d.ts` name.
  const clientTypesPath = resolve(process.cwd(), 'dist/client/client.d.mts');

  app.get('/public-assets/client.d.ts', async (_request, reply) => {
    if (!existsSync(clientTypesPath)) {
      return reply.code(404).type('text/plain; charset=utf-8').send('client.d.ts not built yet - run "npm run build:client"');
    }

    return reply
      .type('text/plain; charset=utf-8')
      .header('Access-Control-Allow-Origin', '*')
      .header('Cache-Control', 'no-cache')
      .send(readFileSync(clientTypesPath, 'utf-8'));
  });

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
