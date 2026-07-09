import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import { env } from '@encryption/src/server/env';
import { API_ERROR_FORBIDDEN } from '@encryption/src/shared/error-codes';

/**
 * Explicit CORS policy for the API: cross-origin browser access to `/api` is
 * DENIED, on purpose and by intent rather than by the incidental absence of
 * Access-Control-Allow-Origin headers (which is what made it "work" before).
 *
 * Every legitimate browser call to `/api` is same-origin: the vault iframe calls
 * it on the vault host, the interface iframe on the interface host. Products never
 * call `/api` from their own origin, they go through the vault over postMessage.
 * Product BACKENDS that read the public registry do so server-to-server, which
 * sends no Origin header and so is never gated here. Making the deny explicit
 * stops a future change from loosening it by accident (e.g. a permissive CORS
 * plugin reflecting every origin).
 *
 * Who may EMBED and DRIVE the service (the parent-domain whitelist) is a SEPARATE
 * control, enforced by `frame-ancestors` and the vault's postMessage origin
 * allowlist, both fed from `ALLOWED_FRAME_ANCESTORS`. It cannot live here: a
 * `<script src>` load (client.js) is not CORS-gated by the browser at all, so no
 * server header can restrict who loads the SDK. The SDK is inert without the
 * iframes it is not allowed to embed.
 */
export const corsPlugin = fp(async (app: FastifyInstance): Promise<void> => {
  app.addHook('onRequest', async (request, reply) => {
    const origin = request.headers.origin;

    // No Origin: same-origin navigation or a non-browser caller. Nothing to gate.
    if (!origin) return;

    // Static assets (iframe HTML, client.js) are not CORS-gated by the browser;
    // only the API surface is considered here.
    if (!request.url.startsWith('/api')) return;

    let originHost: string;
    try {
      originHost = new URL(origin).host;
    } catch {
      return reply.status(403).send({ code: API_ERROR_FORBIDDEN });
    }

    // Same host as the request (the iframe calling its own API host), or one of the
    // configured encryption hosts, is allowed. Comparing hosts, not full origins,
    // keeps this correct in dev (localhost:7200) and behind a TLS-terminating proxy
    // where request.protocol may not reflect the public scheme.
    if (originHost === request.host || originHost === env.VAULT_HOST || originHost === env.UI_HOST) return;

    // Any other origin is a cross-origin browser caller, of which there is no
    // legitimate one. Deny: a preflight gets a bare 204 with no CORS headers (the
    // browser blocks it), an actual request is refused before its handler runs.
    if (request.method === 'OPTIONS') return reply.status(204).send();

    return reply.status(403).send({ code: API_ERROR_FORBIDDEN });
  });
});
