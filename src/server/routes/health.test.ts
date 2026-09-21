import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

const findFirst = vi.fn();

vi.mock('@encryption/src/prisma/client', () => ({ prisma: { user: { findFirst: (...args: unknown[]) => findFirst(...args) } } }));
vi.mock('@encryption/src/server/env', () => ({
  env: { UI_HOST: 'encryption.example.org', VAULT_HOST: 'data.encryption.example.org' },
}));

interface Broken {
  interfacePage?: boolean;
  vaultFile?: boolean;
  api?: boolean;
}

// The three things the server serves, reduced to what the checks look at: a host, a path,
// a status and a content type. `broken` removes one, the way a bad build or a bad
// registration would.
async function serverWith(broken: Broken = {}): Promise<FastifyInstance> {
  const { healthRoute } = await import('@encryption/src/server/routes/health');
  const app = Fastify();

  app.addHook('onRequest', async (request, reply) => {
    const path = request.url.split('?')[0];

    if (request.host === 'encryption.example.org' && path === '/' && !broken.interfacePage) {
      return reply.type('text/html').send('<html></html>');
    }

    if (request.host === 'data.encryption.example.org' && path === '/vault.js' && !broken.vaultFile) {
      return reply.type('application/javascript').send('vault');
    }
  });

  if (!broken.api) app.get('/api/version', async () => ({ version: 'test' }));

  app.register(healthRoute);
  await app.ready();

  return app;
}

describe('health routes', () => {
  let app: FastifyInstance;

  afterEach(async () => {
    await app.close();
    vi.resetModules();
    findFirst.mockReset();
  });

  it('reports ready when the interface, the vault and the API are all served', async () => {
    app = await serverWith();

    const response = await app.inject({ method: 'GET', url: '/health/ready' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'ok', checks: { interface: 'ok', vault: 'ok', api: 'ok' } });
  });

  it.each([
    ['interfacePage', 'interface'],
    ['vaultFile', 'vault'],
    ['api', 'api'],
  ] as const)('is not ready, and says why, when %s is not served', async (what, check) => {
    app = await serverWith({ [what]: true });

    const response = await app.inject({ method: 'GET', url: '/health/ready' });

    expect(response.statusCode).toBe(503);
    expect(response.json().status).toBe('failing');
    expect(response.json().checks[check]).toBe('failing');
  });

  it('stays alive whatever is broken: liveness must never depend on the rest', async () => {
    findFirst.mockRejectedValue(new Error('User was denied access on the database'));
    app = await serverWith({ interfacePage: true, vaultFile: true, api: true });

    expect((await app.inject({ method: 'GET', url: '/health' })).json()).toEqual({ status: 'ok' });
  });

  it('refuses to start on a database that refuses it, or was never migrated', async () => {
    findFirst.mockRejectedValue(new Error('The table `encryption.users` does not exist'));
    app = await serverWith();

    const response = await app.inject({ method: 'GET', url: '/health/startup' });

    expect(response.statusCode).toBe(503);
    expect(response.json().checks).toEqual({ interface: 'ok', vault: 'ok', api: 'ok', database: 'failing' });
    // The reason is for the logs, never for the public body.
    expect(response.body).not.toContain('does not exist');
  });

  it('starts once the database answers on a real table', async () => {
    findFirst.mockResolvedValue(null);
    app = await serverWith();

    const response = await app.inject({ method: 'GET', url: '/health/startup' });

    expect(response.statusCode).toBe(200);
    expect(findFirst).toHaveBeenCalledWith({ select: { id: true } });
  });

  it('keeps a database outage out of readiness: the vault must stay reachable', async () => {
    findFirst.mockRejectedValue(new Error('connection refused'));
    app = await serverWith();

    expect((await app.inject({ method: 'GET', url: '/health/ready' })).statusCode).toBe(200);
    expect(findFirst).not.toHaveBeenCalled();
  });

  it('evaluates once per window, however many probes ask', async () => {
    findFirst.mockResolvedValue(null);
    app = await serverWith();

    await Promise.all([1, 2, 3, 4, 5].map(() => app.inject({ method: 'GET', url: '/health/startup' })));

    expect(findFirst).toHaveBeenCalledTimes(1);
  });
});
