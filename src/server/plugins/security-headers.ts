import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import { env } from '@encryption/src/server/env';

// Wrapped with fastify-plugin to break encapsulation — otherwise the onSend hook
// stays scoped to this plugin and never runs for routes registered on the same
// app instance (API, health, static, vault/UI), so no response would carry these
// headers.
export const securityHeadersPlugin = fp(async (app: FastifyInstance): Promise<void> => {
  const isDev = process.env.NODE_ENV === 'development';
  const frameAncestors = env.ALLOWED_FRAME_ANCESTORS.split(',')
    .map((s) => s.trim())
    .join(' ');

  app.addHook('onSend', async (request, reply) => {
    // `request.host` keeps the port; env.VAULT_HOST/UI_HOST are derived from
    // new URL(...).host, which also keeps it. Comparing against the port-stripped
    // `request.hostname` would never match on a deployment with an explicit port.
    const host = request.host;

    // Common security headers
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Referrer-Policy', 'no-referrer');

    // HSTS only makes sense over HTTPS; emitting it on dev plain-HTTP is noise
    // (and can pin the wrong scheme for localhost).
    if (!isDev) {
      reply.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
    }

    // Deny powerful features everywhere by default; the UI host re-grants camera
    // below for the QR-scan device-pairing flow.
    reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    // In dev mode, Vite injects inline scripts for HMR — relax CSP to allow them.
    // The routing logic is still exercised so host-based dispatch is tested.
    const scriptSrc = isDev ? "'self' 'unsafe-inline'" : "'self'";
    // ws: is only needed for the Vite HMR WebSocket in dev; production never
    // connects to a WebSocket, so it must not widen connect-src there.
    const connectSrc = isDev ? "connect-src 'self' ws:" : "connect-src 'self'";

    if (host === env.VAULT_HOST) {
      // Vault: most restrictive CSP + origin isolation headers. base-uri and
      // form-action are set explicitly because neither falls back to default-src.
      reply.header(
        'Content-Security-Policy',
        `default-src 'none'; script-src ${scriptSrc}; ${connectSrc}; base-uri 'none'; form-action 'none'; frame-ancestors ${frameAncestors}`
      );

      // Cross-Origin isolation headers — reduces attack surface from side-channel attacks
      // (Spectre, etc.) and restricts how other origins can interact with the vault.
      // Note: browser extensions can still bypass these, but it raises the bar.
      if (!isDev) {
        reply.header('Cross-Origin-Embedder-Policy', 'require-corp');
      }
      reply.header('Cross-Origin-Opener-Policy', 'same-origin');
      reply.header('Cross-Origin-Resource-Policy', 'same-origin');
    } else if (host === env.UI_HOST) {
      // UI: allows styles, fonts, and framing the vault. Camera is granted to
      // self so navigator.mediaDevices.getUserMedia can drive the QR-scan pairing.
      reply.header('Permissions-Policy', 'camera=(self), microphone=(), geolocation=()');
      reply.header(
        'Content-Security-Policy',
        `default-src 'none'; script-src ${scriptSrc}; style-src 'self' 'unsafe-inline'; font-src 'self'; ${connectSrc}; img-src 'self'; frame-src ${env.VAULT_URL}; base-uri 'none'; form-action 'none'; frame-ancestors ${frameAncestors}`
      );

      reply.header('Cross-Origin-Opener-Policy', 'same-origin');
      reply.header('Cross-Origin-Resource-Policy', 'same-site');
    } else {
      // API or unknown host
      reply.header('Content-Security-Policy', "default-src 'none'");
    }
  });
});
