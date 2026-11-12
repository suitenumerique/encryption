import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

import { apiCacheControlPlugin } from '@encryption/src/server/plugins/api-cache-control';

async function buildApp() {
  const app = Fastify();
  app.register(apiCacheControlPlugin);
  app.get('/api/me', async () => ({ id: 'user' }));
  app.get('/api/keys', async (_request, reply) => reply.header('Cache-Control', 'private, max-age=60').send({}));
  app.get('/api/boom', async (_request, reply) => reply.status(403).send({ code: 'forbidden' }));
  app.get('/health', async () => ({ status: 'ok' }));
  await app.ready();

  return app;
}

describe('apiCacheControlPlugin', () => {
  it('forbids storing an API answer, errors included', async () => {
    const app = await buildApp();

    for (const url of ['/api/me', '/api/boom']) {
      expect((await app.inject({ method: 'GET', url })).headers['cache-control'], url).toBe('no-store');
    }
  });

  it("keeps a route's own policy", async () => {
    const app = await buildApp();

    expect((await app.inject({ method: 'GET', url: '/api/keys' })).headers['cache-control']).toBe('private, max-age=60');
  });

  it('leaves paths outside the API alone', async () => {
    const app = await buildApp();

    expect((await app.inject({ method: 'GET', url: '/health' })).headers['cache-control']).toBeUndefined();
  });
});
