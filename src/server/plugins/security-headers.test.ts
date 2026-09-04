import Fastify, { type FastifyInstance } from 'fastify';

import { securityHeadersPlugin } from '@encryption/src/server/plugins/security-headers';
import { UI_TRUSTED_TYPES_POLICY, VAULT_TRUSTED_TYPES_POLICY } from '@encryption/src/shared/constants';

// env is mocked so the hosts carry an explicit port, exercising the port-aware
// host matching (the real bug: comparing port-stripped request.hostname against
// a port-carrying env host never matched on a ported deployment).
jest.mock('@encryption/src/server/env', () => ({
  env: {
    VAULT_HOST: 'data.encryption.localhost:7200',
    UI_HOST: 'encryption.localhost:7200',
    VAULT_URL: 'https://data.encryption.localhost:7200',
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

describe('securityHeadersPlugin', () => {
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

    it('omits ws: from connect-src and pins base-uri/form-action on the vault CSP', async () => {
      const headers = await headersFor(VAULT_HOST);
      const csp = headers['content-security-policy'] as string;

      expect(csp).toContain("connect-src 'self'");
      expect(csp).not.toContain('ws:');
      expect(csp).toContain("base-uri 'none'");
      expect(csp).toContain("form-action 'none'");
    });

    it('keeps script-src free of any inline exception on every host', async () => {
      // The runtime config travels as a JSON data block and both direct-access guards
      // live in the bundle, so nothing inline runs. A hash or a nonce reappearing here
      // means something went back to injecting script the SRI cannot cover.
      for (const host of [UI_HOST, VAULT_HOST, 'api.encryption.localhost:7200']) {
        const csp = (await headersFor(host))['content-security-policy'] as string;
        // Scoped to the directive: `style-src` legitimately carries 'unsafe-inline'.
        const scriptSrc = csp.split(';').find((directive) => directive.trim().startsWith('script-src'));

        // The API host declares no script-src at all: `default-src 'none'` covers it.
        expect(scriptSrc?.trim() ?? 'absent').toMatch(/^(absent|script-src 'self' 'wasm-unsafe-eval')$/);
      }
    });

    it('allows WebAssembly compilation, which libsodium cannot run without', async () => {
      // libsodium is compiled to WASM and ships no asm.js fallback: without this,
      // `sodium.ready` rejects and the service performs no cryptography at all.
      // It is present on BOTH document hosts because both bundles carry libsodium.
      for (const host of [VAULT_HOST, UI_HOST]) {
        const csp = (await headersFor(host))['content-security-policy'] as string;

        expect(csp).toContain("'wasm-unsafe-eval'");
        // The narrow grant only: 'unsafe-eval' would also re-open eval and Function.
        expect(csp).not.toContain("'unsafe-eval'");
      }
    });

    it('requires Trusted Types on the vault, allowing only the service worker policy', async () => {
      const headers = await headersFor(VAULT_HOST);
      const csp = headers['content-security-policy'] as string;

      expect(csp).toContain("require-trusted-types-for 'script'");
      expect(csp).toContain(`trusted-types ${VAULT_TRUSTED_TYPES_POLICY}`);

      // `'allow-duplicates'` would let injected code create a second policy under
      // the sanctioned name, which is the whole guarantee this directive buys.
      expect(csp).not.toContain('allow-duplicates');
    });

    it('requires Trusted Types on the UI under its own policy, not the vault one', async () => {
      const csp = (await headersFor(UI_HOST))['content-security-policy'] as string;

      expect(csp).toContain("require-trusted-types-for 'script'");
      expect(csp).toContain(`trusted-types ${UI_TRUSTED_TYPES_POLICY}`);

      // A shared name would let either host mint markup the other one trusts.
      expect(csp).not.toContain(VAULT_TRUSTED_TYPES_POLICY);
      expect(csp).not.toContain('allow-duplicates');
    });

    it('leaves Trusted Types off the API, which serves no document', async () => {
      const csp = (await headersFor('api.encryption.localhost:7200'))['content-security-policy'] as string;

      expect(csp).not.toContain('trusted-types');
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
