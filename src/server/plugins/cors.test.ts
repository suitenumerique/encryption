import Fastify, { type FastifyInstance } from 'fastify';

import { corsPlugin } from '@encryption/src/server/plugins/cors';

jest.mock('@encryption/src/server/env', () => ({
  env: {
    VAULT_HOST: 'data.encryption.localhost:7200',
    UI_HOST: 'encryption.localhost:7200',
  },
}));

const HOST = 'data.encryption.localhost:7200';

async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify();
  await app.register(corsPlugin);
  app.get('/api/vault/items', async () => ({ ok: true }));
  app.get('/client.js', async () => 'sdk');
  await app.ready();

  return app;
}

describe('corsPlugin', () => {
  it('allows a same-origin /api request (Origin equals the request host)', async () => {
    const app = await buildApp();
    const res = await app.inject({ method: 'GET', url: '/api/vault/items', headers: { host: HOST, origin: `https://${HOST}` } });

    expect(res.statusCode).toBe(200);
  });

  it('allows an /api request with no Origin header (same-origin nav or server-to-server)', async () => {
    const app = await buildApp();
    const res = await app.inject({ method: 'GET', url: '/api/vault/items', headers: { host: HOST } });

    expect(res.statusCode).toBe(200);
  });

  it('denies a cross-origin /api request with 403', async () => {
    const app = await buildApp();
    const res = await app.inject({ method: 'GET', url: '/api/vault/items', headers: { host: HOST, origin: 'https://evil.example' } });

    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe('forbidden');
  });

  it('denies a cross-origin /api preflight with a bare 204 and no ACAO', async () => {
    const app = await buildApp();
    const res = await app.inject({ method: 'OPTIONS', url: '/api/vault/items', headers: { host: HOST, origin: 'https://evil.example' } });

    expect(res.statusCode).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('does not gate non-/api paths (client.js loads cross-origin)', async () => {
    const app = await buildApp();
    const res = await app.inject({ method: 'GET', url: '/client.js', headers: { host: HOST, origin: 'https://product-a.example' } });

    expect(res.statusCode).toBe(200);
  });
});
