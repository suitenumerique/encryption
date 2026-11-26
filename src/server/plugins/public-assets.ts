import fastifyStatic from '@fastify/static';
import type { FastifyInstance } from 'fastify';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Assets that are fetched from OUTSIDE a browser tab on our origin: the logo
 * embedded in notification emails (loaded by a mail client), the SDK type
 * declaration an integrating product vendors, and the maintenance tool operators
 * download. They are served cross-origin (the CORP exception lives
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

  app.get('/public-assets/client.d.ts', { schema: { hide: true } }, async (_request, reply) => {
    if (!existsSync(clientTypesPath)) {
      return reply.code(404).type('text/plain; charset=utf-8').send('client.d.ts not built yet - run "npm run build:client"');
    }

    return reply.type('text/plain; charset=utf-8').header('Cache-Control', 'no-cache').send(readFileSync(clientTypesPath, 'utf-8'));
  });

  // The maintenance tool (architecture.md, Appendix E): one HTML file operators
  // download and open from disk on an isolated computer. Shipped in the image so
  // every deployment hands out the build matching its own vault, without anyone
  // having to build it. It must never RUN on this origin, where it would share the
  // interface's storage: `attachment` makes the browser save it instead of
  // rendering it, and `sandbox` would strip it of the origin if one rendered anyway.
  // Never indexed either: robots.txt already keeps crawlers off every path, the
  // header covers an engine that reaches the URL through a link anyway, and the
  // file carries the same instruction in its own <meta name="robots">.
  const maintenanceToolPath = resolve(process.cwd(), 'dist/maintenance/maintenance-tool.html');

  app.get('/public-assets/maintenance-tool.html', { schema: { hide: true } }, async (_request, reply) => {
    if (!existsSync(maintenanceToolPath)) {
      return reply.code(404).type('text/plain; charset=utf-8').send('maintenance-tool.html not built yet - run "npm run build:maintenance"');
    }

    return reply
      .type('text/html; charset=utf-8')
      .header('Content-Disposition', 'attachment; filename="lasuite-encryption-maintenance-tool.html"')
      .header('Content-Security-Policy', "sandbox; default-src 'none'")
      .header('X-Robots-Tag', 'noindex, nofollow')
      .header('Cache-Control', 'no-cache')
      .send(readFileSync(maintenanceToolPath));
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
