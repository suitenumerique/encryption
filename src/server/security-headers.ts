import { env } from '@encryption/src/server/env';
import { UI_TRUSTED_TYPES_POLICY, VAULT_TRUSTED_TYPES_POLICY } from '@encryption/src/shared/constants';

/**
 * The headers as a plain map, computed away from any Fastify hook, because two
 * different paths have to emit them: the `onSend` hook for everything Fastify serves,
 * and the dev plugin, where Vite's connect middleware writes to the raw response and
 * never reaches that hook. Sharing one function is what keeps development honest;
 * dev used to carry NO policy at all, which is why a blocked runtime-config script and
 * a blocked WebAssembly compilation both went unnoticed until production.
 */
export function buildSecurityHeaders(host: string, url: string): Record<string, string> {
  const isDev = process.env.NODE_ENV === 'development';

  // Public assets are meant to be embedded cross-origin — the logo in a mail client,
  // the fonts in a generated PDF — so they get a relaxed CORP and skip the iframe-only
  // CSP. This is the ONLY exception; everything else below stays same-site/same-origin.
  if (url.startsWith('/public-assets/')) {
    return { 'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Resource-Policy': 'cross-origin' };
  }

  const frameAncestors = env.ALLOWED_FRAME_ANCESTORS.split(',')
    .map((s) => s.trim())
    .join(' ');

  const headers: Record<string, string> = {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    // Denied everywhere by default; the UI host re-grants camera below for QR pairing.
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  };

  // HSTS only makes sense over HTTPS; emitting it on dev plain-HTTP is noise (and can
  // pin the wrong scheme for localhost).
  if (!isDev) {
    headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains';
  }

  // In dev, Vite injects inline scripts for HMR. Production needs no exception: the
  // runtime config travels as a JSON data block and both direct-access guards live in
  // the bundle, so nothing inline runs and `'self'` covers every executed byte.
  //
  // `'wasm-unsafe-eval'` is NOT optional: libsodium is compiled to WebAssembly and
  // ships no asm.js fallback, so without it `sodium.ready` rejects and the service
  // performs no cryptography at all. It is the narrow grant — it permits compiling
  // WebAssembly and nothing else, unlike `'unsafe-eval'`, which would also re-open
  // `eval` and `new Function`. CSP has no hash or integrity mechanism for WASM.
  const scriptSrc = isDev ? "'self' 'unsafe-inline' 'wasm-unsafe-eval'" : "'self' 'wasm-unsafe-eval'";
  // ws: is only needed for the Vite HMR WebSocket in dev; production never connects to
  // a WebSocket, so it must not widen connect-src there.
  const connectSrc = isDev ? "connect-src 'self' ws:" : "connect-src 'self'";

  if (host === env.VAULT_HOST) {
    // Vault: most restrictive CSP + origin isolation. base-uri and form-action are set
    // explicitly because neither falls back to default-src.
    //
    // `require-trusted-types-for 'script'` closes what `script-src` cannot. `'self'`
    // without `'unsafe-inline'` already kills inline handlers, but it authorizes ANY
    // same-origin script URL, and build-time SRI does not reach a script element
    // created at runtime. This makes the browser refuse a plain string at every
    // injection sink, enforced independently of `script-src` so they stay shut even if
    // that directive is ever relaxed. `trusted-types` names the only policy allowed to
    // exist, and the vault needs exactly one because `ServiceWorkerContainer.register()`
    // is itself a TrustedScriptURL sink. That policy is narrow rather than trusted: it
    // mints only the worker path, so a reference to it is worth nothing. The name is
    // deliberately not `default`, which would be reachable as `trustedTypes.defaultPolicy`
    // and would convert strings at every sink.
    headers['Content-Security-Policy'] =
      `default-src 'none'; script-src ${scriptSrc}; ${connectSrc}; base-uri 'none'; form-action 'none'; frame-ancestors ${frameAncestors}; require-trusted-types-for 'script'; trusted-types ${VAULT_TRUSTED_TYPES_POLICY}`;

    // Reduces the attack surface from side-channel attacks (Spectre, etc.) and
    // restricts how other origins can interact with the vault. Browser extensions can
    // still bypass these, but it raises the bar.
    if (!isDev) {
      headers['Cross-Origin-Embedder-Policy'] = 'require-corp';
    }
    headers['Cross-Origin-Opener-Policy'] = 'same-origin';
    headers['Cross-Origin-Resource-Policy'] = 'same-origin';
  } else if (host === env.UI_HOST) {
    // UI: allows styles, fonts, and framing the vault. Camera is granted to self so
    // navigator.mediaDevices.getUserMedia can drive the QR-scan pairing.
    headers['Permissions-Policy'] = 'camera=(self), microphone=(), geolocation=()';
    // Same Trusted Types enforcement as the vault. The interface does render markup it
    // did not build node by node (highlighted code, a diagram in the internal
    // architecture doc), so it names a policy of its own rather than none, and
    // `src/ui/trusted-markup.ts` is the single place those conversions happen.
    headers['Content-Security-Policy'] =
      `default-src 'none'; script-src ${scriptSrc}; style-src 'self' 'unsafe-inline'; font-src 'self'; ${connectSrc}; img-src 'self'; frame-src ${env.VAULT_URL}; base-uri 'none'; form-action 'none'; frame-ancestors ${frameAncestors}; require-trusted-types-for 'script'; trusted-types ${UI_TRUSTED_TYPES_POLICY}`;

    headers['Cross-Origin-Opener-Policy'] = 'same-origin';
    headers['Cross-Origin-Resource-Policy'] = 'same-site';
  } else {
    // API or unknown host
    headers['Content-Security-Policy'] = "default-src 'none'";
  }

  return headers;
}
