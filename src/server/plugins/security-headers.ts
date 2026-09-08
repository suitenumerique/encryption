import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import { env } from '@encryption/src/server/env';
import { UI_TRUSTED_TYPES_POLICY, VAULT_TRUSTED_TYPES_POLICY } from '@encryption/src/shared/constants';

// Wrapped with fastify-plugin to break encapsulation — otherwise the hook stays scoped
// to this plugin and never runs for routes registered on the same app instance (API,
// health, static, vault/UI), so no response would carry these headers.
//
// `onRequest` writing to `reply.raw`, NOT `onSend` writing to `reply`. In development
// the Vite middleware (via @fastify/middie, which itself runs in the onRequest phase)
// answers by writing to the raw response and never calls `reply.send()`, so the whole
// reply lifecycle including `onSend` is skipped and those responses carried no policy
// at all. Development therefore enforced nothing, which is how a CSP-blocked runtime
// config and a CSP-blocked WebAssembly compilation both reached production unnoticed.
// Setting them on the raw response before any middleware runs covers both paths: Node
// merges headers set with `setHeader()` into the later `writeHead()` Fastify does for
// its own replies. This plugin must therefore stay registered BEFORE the Vite plugin,
// since Fastify runs onRequest hooks in registration order.
export const securityHeadersPlugin = fp(async (app: FastifyInstance): Promise<void> => {
  const isDev = process.env.NODE_ENV === 'development';
  const productFrameAncestors = env.ALLOWED_FRAME_ANCESTORS.split(',')
    .map((s) => s.trim())
    .join(' '); // The products allowed to embed either iframe.
  const vaultFrameAncestors = `${productFrameAncestors} ${env.UI_URL}`; // The vault has one embedder the interface does not: the interface itself.
  // Only the interface talks to the OIDC provider: oidc-client-ts fetches its discovery
  // document and JWKS, and the lazy token refresh POSTs to its token endpoint. The
  // vault never does, so it must not get this.
  const oidcOrigin = new URL(env.OIDC_ISSUER).origin;

  app.addHook('onRequest', async (request, reply) => {
    // Public assets are meant to be embedded cross-origin — the logo in a mail
    // client, the fonts in a generated PDF — so they get a relaxed CORP and skip
    // the iframe-only CSP. This is the ONLY exception; everything else below stays
    // same-site / same-origin.
    if (request.url.startsWith('/public-assets/')) {
      reply.raw.setHeader('X-Content-Type-Options', 'nosniff');
      reply.raw.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');

      return;
    }

    // `request.host` keeps the port; env.VAULT_HOST/UI_HOST are derived from
    // new URL(...).host, which also keeps it. Comparing against the port-stripped
    // `request.hostname` would never match on a deployment with an explicit port.
    const host = request.host;

    // Common security headers
    reply.raw.setHeader('X-Content-Type-Options', 'nosniff');
    reply.raw.setHeader('Referrer-Policy', 'no-referrer');

    // HSTS only makes sense over HTTPS; emitting it on dev plain-HTTP is noise
    // (and can pin the wrong scheme for localhost).
    if (!isDev) {
      reply.raw.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
    }

    // Deny powerful features everywhere by default; the UI host re-grants camera
    // below for the QR-scan device-pairing flow.
    reply.raw.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    // In dev mode, Vite injects inline scripts for HMR — relax CSP to allow them.
    // The routing logic is still exercised so host-based dispatch is tested.
    const scriptSrc = isDev ? "'self' 'unsafe-inline' 'wasm-unsafe-eval'" : "'self' 'wasm-unsafe-eval'";
    // ws: is only needed for the Vite HMR WebSocket in dev; production never
    // connects to a WebSocket, so it must not widen connect-src there.
    const connectSrc = isDev ? "'self' ws:" : "'self'";

    if (host === env.VAULT_HOST) {
      // Vault: most restrictive CSP + origin isolation headers. base-uri and
      // form-action are set explicitly because neither falls back to default-src.
      reply.raw.setHeader(
        'Content-Security-Policy',
        `default-src 'none'; script-src ${scriptSrc}; connect-src ${connectSrc}; base-uri 'none'; form-action 'none'; frame-ancestors ${vaultFrameAncestors}; require-trusted-types-for 'script'; trusted-types ${VAULT_TRUSTED_TYPES_POLICY}`
      );

      // Cross-Origin isolation headers — reduces attack surface from side-channel attacks
      // (Spectre, etc.) and restricts how other origins can interact with the vault.
      // Note: browser extensions can still bypass these, but it raises the bar.
      if (!isDev) {
        reply.raw.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
      }
      reply.raw.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
      reply.raw.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    } else if (host === env.UI_HOST) {
      // UI: allows styles, fonts, and framing the vault. Camera is granted to
      // self so navigator.mediaDevices.getUserMedia can drive the QR-scan pairing.
      // `data:` in font-src: Cunningham inlines its icon font inside its own stylesheet.
      reply.raw.setHeader('Permissions-Policy', 'camera=(self), microphone=(), geolocation=()');
      reply.raw.setHeader(
        'Content-Security-Policy',
        `default-src 'none'; script-src ${scriptSrc}; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src ${connectSrc} ${oidcOrigin}; img-src 'self'; frame-src ${env.VAULT_URL}; base-uri 'none'; form-action 'none'; frame-ancestors ${productFrameAncestors}; require-trusted-types-for 'script'; trusted-types ${UI_TRUSTED_TYPES_POLICY}`
      );

      reply.raw.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
      reply.raw.setHeader('Cross-Origin-Resource-Policy', 'same-site');
    } else {
      // API or unknown host
      reply.raw.setHeader('Content-Security-Policy', "default-src 'none'");
    }
  });
});
