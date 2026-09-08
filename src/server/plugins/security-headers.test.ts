import middie from '@fastify/middie';
import Fastify, { type FastifyInstance } from 'fastify';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { securityHeadersPlugin } from '@encryption/src/server/plugins/security-headers';

// env is mocked so the hosts carry an explicit port, exercising the port-aware
// host matching (the real bug: comparing port-stripped request.hostname against
// a port-carrying env host never matched on a ported deployment).
vi.mock('@encryption/src/server/env', () => ({
  env: {
    VAULT_HOST: 'data.encryption.localhost:7200',
    UI_HOST: 'encryption.localhost:7200',
    VAULT_URL: 'https://data.encryption.localhost:7200',
    OIDC_ISSUER: 'https://keycloak.example:8443/realms/encryption',
    UI_URL: 'https://encryption.localhost:7200',
    ALLOWED_FRAME_ANCESTORS: 'https://product-a.example, https://product-b.example',
  },
}));

const VAULT_HOST = 'data.encryption.localhost:7200';
const UI_HOST = 'encryption.localhost:7200';

async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify();

  await app.register(securityHeadersPlugin);
  app.get('/', async () => 'ok');
  await app.ready();

  return app;
}

async function headersFor(host: string) {
  const app = await buildApp();
  const response = await app.inject({ method: 'GET', url: '/', headers: { host } });

  return response.headers;
}

function trustedTypesOf(csp: string): string | undefined {
  return csp
    .split(';')
    .map((directive) => directive.trim())
    .find((directive) => directive.startsWith('trusted-types'));
}

describe('securityHeadersPlugin', () => {
  // The failure this guards against: in development the Vite middleware answers by
  // writing to the raw response and never calls reply.send(), so an `onSend` hook was
  // skipped entirely and those responses carried no policy at all. That is how a
  // CSP-blocked runtime config and a CSP-blocked WebAssembly compilation both reached
  // production unnoticed, the policy existing only on a path nobody runs locally.
  it('still applies to a response a middleware wrote directly, as Vite does in dev', async () => {
    const app = Fastify();

    await app.register(securityHeadersPlugin);
    await app.register(middie);
    app.use((_req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html>');
    });
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/', headers: { host: VAULT_HOST } });

    expect(response.headers['content-security-policy']).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(response.headers['x-content-type-options']).toBe('nosniff');
  });

  const originalNodeEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalNodeEnv;
  });

  describe('in production', () => {
    beforeEach(() => {
      process.env.NODE_ENV = 'production';
    });

    it('grants camera to self on the UI host so QR-scan pairing can run', async () => {
      const headers = await headersFor(UI_HOST);

      expect(headers['permissions-policy']).toBe('camera=(self), microphone=(), geolocation=()');
    });

    it('hard-denies camera on the vault host', async () => {
      const headers = await headersFor(VAULT_HOST);

      expect(headers['permissions-policy']).toBe('camera=(), microphone=(), geolocation=()');
    });

    it('hard-denies camera on an unknown/API host', async () => {
      const headers = await headersFor('api.example:7200');

      expect(headers['permissions-policy']).toBe('camera=(), microphone=(), geolocation=()');
    });

    it('matches the vault host WITH its port and emits the isolation + HSTS headers', async () => {
      const headers = await headersFor(VAULT_HOST);

      // Would be a bare "default-src 'none'" (the else branch) if the port-carrying
      // host failed to match.
      expect(headers['content-security-policy']).toContain("script-src 'self'");
      expect(headers['cross-origin-embedder-policy']).toBe('require-corp');
      expect(headers['strict-transport-security']).toBe('max-age=63072000; includeSubDomains');
    });

    it('grants the narrow wasm-unsafe-eval on both iframe hosts', async () => {
      for (const host of [VAULT_HOST, UI_HOST]) {
        const csp = (await headersFor(host))['content-security-policy'] as string;
        const scriptSrc = csp
          .split(';')
          .map((directive) => directive.trim())
          .find((directive) => directive.startsWith('script-src'));

        // Asserted whole rather than with toContain: libsodium compiles WebAssembly and
        // its asm.js backup does not rescue a CSP refusal, so dropping this leaves the
        // service unable to do any crypto, while `'unsafe-eval'` is a substring of
        // `'wasm-unsafe-eval'` and only an equality check can prove the wider grant did
        // not slip in alongside it.
        expect(scriptSrc).toBe("script-src 'self' 'wasm-unsafe-eval'");
      }
    });

    it('requires trusted types for script on both iframes, each naming a single policy', async () => {
      const vaultCsp = (await headersFor(VAULT_HOST))['content-security-policy'] as string;
      const uiCsp = (await headersFor(UI_HOST))['content-security-policy'] as string;

      expect(vaultCsp).toContain("require-trusted-types-for 'script'");
      expect(uiCsp).toContain("require-trusted-types-for 'script'");

      expect(trustedTypesOf(vaultCsp)).toBe('trusted-types vault-service-worker');
      expect(trustedTypesOf(uiCsp)).toBe('trusted-types interface-markup');
    });

    it('does not give the vault the interface markup policy', async () => {
      const vaultCsp = (await headersFor(VAULT_HOST))['content-security-policy'] as string;

      expect(vaultCsp).not.toContain('interface-markup');
    });

    it('lets the interface frame the vault, not only the products', async () => {
      const csp = (await headersFor(VAULT_HOST))['content-security-policy'] as string;

      // The interface drives every privileged operation through its own vault iframe.
      // Without its origin here the vault refuses to load and the interface hangs.
      expect(csp).toContain('frame-ancestors https://product-a.example https://product-b.example https://encryption.localhost:7200');
    });

    it('lets the interface reach the OIDC provider, by origin and not by issuer path', async () => {
      const uiCsp = (await headersFor(UI_HOST))['content-security-policy'] as string;
      const vaultCsp = (await headersFor(VAULT_HOST))['content-security-policy'] as string;

      // The origin, so discovery/JWKS/token all resolve; the issuer's /realms path
      // would only authorize that one path prefix.
      expect(uiCsp).toContain("connect-src 'self' https://keycloak.example:8443;");
      // The vault never talks to the provider, so it keeps the narrow set.
      expect(vaultCsp).toContain("connect-src 'self';");
      expect(vaultCsp).not.toContain('keycloak.example');
    });

    it('omits ws: from connect-src and pins base-uri/form-action on the vault CSP', async () => {
      const headers = await headersFor(VAULT_HOST);
      const csp = headers['content-security-policy'] as string;

      expect(csp).toContain("connect-src 'self'");
      expect(csp).not.toContain('ws:');
      expect(csp).toContain("base-uri 'none'");
      expect(csp).toContain("form-action 'none'");
    });

    it('omits ws: from connect-src and pins base-uri/form-action on the UI CSP', async () => {
      const headers = await headersFor(UI_HOST);
      const csp = headers['content-security-policy'] as string;

      expect(csp).toContain("connect-src 'self'");
      expect(csp).not.toContain('ws:');
      expect(csp).toContain("base-uri 'none'");
      expect(csp).toContain("form-action 'none'");
      expect(csp).toContain('frame-src https://data.encryption.localhost:7200');
    });
  });

  describe('in development', () => {
    beforeEach(() => {
      process.env.NODE_ENV = 'development';
    });

    it('allows the Vite HMR WebSocket via ws: in connect-src', async () => {
      const headers = await headersFor(VAULT_HOST);

      expect(headers['content-security-policy']).toContain("connect-src 'self' ws:");
    });

    it('keeps wasm-unsafe-eval alongside the HMR inline exception', async () => {
      const headers = await headersFor(VAULT_HOST);

      expect(headers['content-security-policy']).toContain("script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'");
    });

    it('does not emit HSTS over dev plain-HTTP', async () => {
      const headers = await headersFor(VAULT_HOST);

      expect(headers['strict-transport-security']).toBeUndefined();
    });

    it('does not emit COEP on the vault in dev', async () => {
      const headers = await headersFor(VAULT_HOST);

      expect(headers['cross-origin-embedder-policy']).toBeUndefined();
    });
  });
});
