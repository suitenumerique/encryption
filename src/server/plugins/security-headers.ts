import type { FastifyInstance } from 'fastify';

import { env } from '@encryption/src/server/env';

export async function securityHeadersPlugin(app: FastifyInstance): Promise<void> {
  const isDev = process.env.NODE_ENV === 'development';
  const frameAncestors = env.ALLOWED_FRAME_ANCESTORS.split(',')
    .map((s) => s.trim())
    .join(' ');

  app.addHook('onSend', async (request, reply) => {
    const host = request.hostname;

    // Common security headers
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
    reply.header('Referrer-Policy', 'no-referrer');
    reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    // In dev mode, Vite injects inline scripts for HMR — relax CSP to allow them.
    // The routing logic is still exercised so host-based dispatch is tested.
    const scriptSrc = isDev ? "'self' 'unsafe-inline'" : "'self'";

    if (host === env.VAULT_HOST) {
      // Vault: most restrictive CSP + origin isolation headers
      reply.header('Content-Security-Policy', `default-src 'none'; script-src ${scriptSrc}; connect-src 'self' ws:; frame-ancestors ${frameAncestors}`);

      // Cross-Origin isolation headers — reduces attack surface from side-channel attacks
      // (Spectre, etc.) and restricts how other origins can interact with the vault.
      // Note: browser extensions can still bypass these, but it raises the bar.
      if (!isDev) {
        reply.header('Cross-Origin-Embedder-Policy', 'require-corp');
      }
      reply.header('Cross-Origin-Opener-Policy', 'same-origin');
      reply.header('Cross-Origin-Resource-Policy', 'same-origin');
    } else if (host === env.UI_HOST) {
      // UI: allows styles, fonts, and framing the vault
      reply.header(
        'Content-Security-Policy',
        `default-src 'none'; script-src ${scriptSrc}; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self' ws:; img-src 'self'; frame-src ${env.VAULT_URL}; frame-ancestors ${frameAncestors}`
      );

      reply.header('Cross-Origin-Opener-Policy', 'same-origin');
      reply.header('Cross-Origin-Resource-Policy', 'same-site');
    } else {
      // API or unknown host
      reply.header('Content-Security-Policy', "default-src 'none'");
    }
  });
}
