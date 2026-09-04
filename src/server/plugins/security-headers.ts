import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import { buildSecurityHeaders } from '@encryption/src/server/security-headers';

// Wrapped with fastify-plugin to break encapsulation — otherwise the onSend hook stays
// scoped to this plugin and never runs for routes registered on the same app instance
// (API, health, static, vault/UI), so no response would carry these headers.
//
// This covers everything Fastify serves. In development the Vite middleware answers
// before the reply lifecycle, so `vite-dev.ts` emits the same headers itself.
export const securityHeadersPlugin = fp(async (app: FastifyInstance): Promise<void> => {
  app.addHook('onSend', async (request, reply) => {
    // `request.host` keeps the port; env.VAULT_HOST/UI_HOST are derived from
    // new URL(...).host, which also keeps it. Comparing against the port-stripped
    // `request.hostname` would never match on a deployment with an explicit port.
    for (const [name, value] of Object.entries(buildSecurityHeaders(request.host, request.url))) {
      reply.header(name, value);
    }
  });
});
