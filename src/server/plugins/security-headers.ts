import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import { buildSecurityHeaders } from '@encryption/src/server/security-headers';

// Wrapped with fastify-plugin to break encapsulation — otherwise the hook stays scoped
// to this plugin and never runs for routes registered on the same app instance (API,
// health, static, vault/UI), so no response would carry these headers.
//
// `onRequest` writing to `reply.raw`, NOT `onSend` writing to `reply`. In development
// the Vite middleware (via @fastify/middie, which itself runs in the onRequest phase)
// answers by writing to the raw response and never calls `reply.send()`, so the whole
// reply lifecycle including `onSend` is skipped and those responses carried no policy
// at all. Setting them on the raw response before any middleware runs covers both
// paths: Node keeps headers set with `setHeader()` when Fastify later calls
// `writeHead()` for its own replies. This plugin must therefore stay registered before
// the Vite plugin, since Fastify runs onRequest hooks in registration order.
export const securityHeadersPlugin = fp(async (app: FastifyInstance): Promise<void> => {
  app.addHook('onRequest', async (request, reply) => {
    // `request.host` keeps the port; env.VAULT_HOST/UI_HOST are derived from
    // new URL(...).host, which also keeps it. Comparing against the port-stripped
    // `request.hostname` would never match on a deployment with an explicit port.
    for (const [name, value] of Object.entries(buildSecurityHeaders(request.host, request.url))) {
      reply.raw.setHeader(name, value);
    }
  });
});
