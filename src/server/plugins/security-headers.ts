import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import { env } from '@encryption/src/server/env';
import { BROWSER_REPORT_PATH, UI_TRUSTED_TYPES_POLICY, VAULT_TRUSTED_TYPES_POLICY } from '@encryption/src/shared/constants';
import { parseOriginAllowlist } from '@encryption/src/shared/origin-allowlist';

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
/** The client SDK as products load it, served by the vault host. */
const SDK_PATHS = new Set(['/client.js', '/client.mjs', '/client.d.ts']);
/** The brand fonts the emails reference, served by the interface host. */
export const FONTS_PATH_PREFIX = '/assets/fonts/';

export const securityHeadersPlugin = fp(async (app: FastifyInstance): Promise<void> => {
  const isDev = process.env.NODE_ENV === 'development';
  const productFrameAncestors = parseOriginAllowlist(env.ALLOWED_FRAME_ANCESTORS).join(' '); // The products allowed to embed either iframe.
  const vaultFrameAncestors = `${productFrameAncestors} ${env.UI_URL}`; // The vault has one embedder the interface does not: the interface itself.

  app.addHook('onRequest', async (request, reply) => {
    const path = request.url.split('?')[0];

    // Two kinds of files are meant to be fetched from another origin, so they get
    // a relaxed CORP and skip the iframe-only CSP: the public assets (the logo in
    // a mail client, the SDK type declaration) and the client SDK, which a
    // product loads with a plain <script src> from its own origin, a no-cors
    // request that `same-origin` would make the browser refuse. The SDK is inert
    // without the iframes, and who may embed those stays governed by
    // frame-ancestors. The brand fonts join them, for the emails read in a
    // webmail. Everything else below stays same-site / same-origin.
    if (
      request.url.startsWith('/public-assets/') ||
      (request.host === env.VAULT_HOST && SDK_PATHS.has(path)) ||
      (request.host === env.UI_HOST && path.startsWith(FONTS_PATH_PREFIX))
    ) {
      reply.raw.setHeader('X-Content-Type-Options', 'nosniff');
      reply.raw.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');

      return;
    }

    // The sign-in tab's first page: it asks the interface iframe that opened it for
    // the sign-in's parameters through `window.opener`; see the COOP exception below.
    const isLoginPage = path === '/login';

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

    // Without reporting, the browser blocks a violation silently and nobody ever learns it happened.
    reply.raw.setHeader('Reporting-Endpoints', `default="${request.protocol}://${request.host}${BROWSER_REPORT_PATH}"`);

    const reporting = `report-to default; report-uri ${BROWSER_REPORT_PATH}`;

    if (host === env.VAULT_HOST) {
      // Vault: most restrictive CSP + origin isolation headers. base-uri and
      // form-action are set explicitly because neither falls back to default-src.
      reply.raw.setHeader(
        'Content-Security-Policy',
        `default-src 'none'; script-src ${scriptSrc}; connect-src ${connectSrc}; base-uri 'none'; form-action 'none'; frame-ancestors ${vaultFrameAncestors}; require-trusted-types-for 'script'; trusted-types ${VAULT_TRUSTED_TYPES_POLICY}; ${reporting}`
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
        `default-src 'none'; script-src ${scriptSrc}; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src ${connectSrc}; img-src 'self'; frame-src ${env.VAULT_URL}; base-uri 'none'; form-action 'none'; frame-ancestors ${productFrameAncestors}; require-trusted-types-for 'script'; trusted-types ${UI_TRUSTED_TYPES_POLICY}; ${reporting}`
      );

      // COOP is deliberately `unsafe-none` on /login, the sign-in tab's first page:
      // `same-origin` there would load it with `window.opener` already null, and the tab
      // could not ask the interface iframe that opened it for the sign-in's parameters.
      // Sent explicitly rather than left out, the browser's default being the same, so a
      // proxy adding a COOP where none is set cannot break the sign-in. Past that page
      // the opener is no longer needed (the result travels back through the server,
      // src/server/routes/auth.ts), so the redirect to the provider and the callback send
      // `same-origin` like the rest. Measured in Chromium and Firefox: the handshake on
      // /login works, and the tab still closes itself from a callback sending COOP.
      reply.raw.setHeader('Cross-Origin-Opener-Policy', isLoginPage ? 'unsafe-none' : 'same-origin');
      reply.raw.setHeader('Cross-Origin-Resource-Policy', 'same-site');
    } else {
      // API or unknown host
      reply.raw.setHeader('Content-Security-Policy', `default-src 'none'; ${reporting}`);
    }
  });
});
