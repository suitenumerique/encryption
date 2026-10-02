import Fastify, { type FastifyInstance } from 'fastify';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@encryption/src/server/env', () => ({
  env: {
    UI_HOST: 'encryption.example.org',
    VAULT_HOST: 'data.encryption.example.org',
    UI_URL: 'https://encryption.example.org',
    VAULT_URL: 'https://data.encryption.example.org',
    ALLOWED_FRAME_ANCESTORS: 'https://docs.example.org',
    OIDC_ISSUER: 'https://auth.example.org',
    OIDC_CLIENT_ID: 'encryption',
    OIDC_REDIRECT_URI: 'https://encryption.example.org/auth/callback',
    DOCS_ENABLED: true,
  },
}));

// Registered the way server.ts does it, on top of a route of the server's own. The pages
// and the vault files are not routes: they are answered by hooks, and a hook only runs
// for a path that matches no route when its plugin is not encapsulated. That is invisible
// in development (Vite serves) and to a health check, so it is asserted here.
describe('production static serving', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    const root = mkdtempSync(join(tmpdir(), 'dist-'));

    mkdirSync(join(root, 'dist/ui/assets'), { recursive: true });
    mkdirSync(join(root, 'dist/vault'), { recursive: true });
    mkdirSync(join(root, 'dist/client'), { recursive: true });
    writeFileSync(join(root, 'dist/ui/interface.html'), '<html><head></head><body>interface</body></html>');
    writeFileSync(join(root, 'dist/vault/bridge.html'), '<html><head></head><body>bridge</body></html>');
    writeFileSync(join(root, 'dist/vault/vault.js'), 'vault');
    writeFileSync(join(root, 'dist/client/client.js'), 'client');
    vi.spyOn(process, 'cwd').mockReturnValue(root);

    const { staticUiPlugin } = await import('@encryption/src/server/plugins/static-ui');
    const { staticVaultPlugin } = await import('@encryption/src/server/plugins/static-vault');

    app = Fastify();
    app.get('/health', async () => ({ status: 'ok' }));
    app.register(staticVaultPlugin);
    app.register(staticUiPlugin);
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
    vi.restoreAllMocks();
  });

  function get(host: string, url: string) {
    return app.inject({ method: 'GET', url, headers: { host } });
  }

  it('serves the interface page for any page path of the interface host', async () => {
    for (const url of ['/', '/login', '/auth/callback?code=abc']) {
      const response = await get('encryption.example.org', url);

      expect(response.statusCode, url).toBe(200);
      expect(response.headers['content-type'], url).toContain('text/html');
      expect(response.body, url).toContain('interface');
    }
  });

  it('serves the vault files on the vault host only', async () => {
    expect((await get('data.encryption.example.org', '/client.js')).body).toBe('client');
    expect((await get('data.encryption.example.org', '/vault.js')).body).toBe('vault');
    expect((await get('data.encryption.example.org', '/bridge.html')).statusCode).toBe(200);

    expect((await get('encryption.example.org', '/client.js')).body).not.toBe('client');
    expect((await get('another.example.org', '/client.js')).statusCode).toBe(404);
  });

  it("leaves the server's own paths alone, on every host", async () => {
    for (const host of ['encryption.example.org', 'data.encryption.example.org', '10.0.0.1:7200']) {
      const response = await get(host, '/health');

      expect(response.json(), host).toEqual({ status: 'ok' });
    }
  });

  it('serves nothing to a host it does not know', async () => {
    expect((await get('another.example.org', '/')).statusCode).toBe(404);
    expect((await get('data.encryption.example.org', '/')).statusCode).toBe(404);
  });
});
