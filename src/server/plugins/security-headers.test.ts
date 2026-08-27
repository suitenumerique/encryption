import Fastify, { type FastifyInstance } from 'fastify';

import { securityHeadersPlugin } from '@encryption/src/server/plugins/security-headers';

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

    it('omits ws: from connect-src and pins base-uri/form-action on the UI CSP', async () => {
      const headers = await headersFor(UI_HOST);
      const csp = headers['content-security-policy'] as string;

      expect(csp).toContain("connect-src 'self'");
      expect(csp).not.toContain('ws:');
      expect(csp).toContain("base-uri 'none'");
      expect(csp).toContain("form-action 'none'");
      expect(csp).toContain('frame-src https://data.encryption.localhost:7200');
    });

    it('advertises a same-origin reporting endpoint on every host', async () => {
      for (const host of [VAULT_HOST, UI_HOST, 'api.example.com']) {
        const headers = await headersFor(host);

        expect(headers['reporting-endpoints']).toBe(`default="http://${host}/api/browser-reports"`);
        expect(headers['content-security-policy']).toContain('report-to default');
        expect(headers['content-security-policy']).toContain('report-uri /api/browser-reports');
      }
    });

    it('requires Trusted Types on the vault and forbids creating a policy', async () => {
      const csp = (await headersFor(VAULT_HOST))['content-security-policy'] as string;

      expect(csp).toContain("require-trusted-types-for 'script'");
      expect(csp).toContain("trusted-types 'none'");
    });

    it('does not impose Trusted Types on the UI, which renders a real React tree', async () => {
      expect((await headersFor(UI_HOST))['content-security-policy']).not.toContain('require-trusted-types-for');
    });

    it('keeps the API host locked to default-src none while still reporting', async () => {
      const csp = (await headersFor('api.example.com'))['content-security-policy'] as string;

      expect(csp.startsWith("default-src 'none'")).toBe(true);
      expect(csp).toContain('report-to default');
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
