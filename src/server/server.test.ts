import Fastify from 'fastify';
import { z } from 'zod';

import { errorHandler } from '@encryption/src/server/server';
import { API_ERROR_INTERNAL, API_ERROR_INVALID_REQUEST } from '@encryption/src/shared/error-codes';

// env / prisma are mocked so importing server.ts (which pulls the routes) does
// not run the real env validator or instantiate a database client under test.
jest.mock('@encryption/src/server/env', () => ({
  env: {
    VAULT_HOST: 'data.encryption.localhost',
    UI_HOST: 'encryption.localhost',
    VAULT_URL: 'https://data.encryption.localhost',
    ALLOWED_FRAME_ANCESTORS: 'https://a.example',
    OIDC_JWKS_URL: 'https://issuer.example/jwks',
    OIDC_ISSUER: 'https://issuer.example',
    OIDC_SERVER_CLIENT_ID: 'encryption',
  },
}));

// This suite only exercises the error handler, it never reaches a query, so it
// stubs the client rather than booting the in-process database of the
// route suites (src/prisma/testing.ts).
jest.mock('@encryption/src/prisma/client', () => ({ prisma: {} }));

// jose is ESM-only and cannot be required by ts-jest (CommonJS); server.ts pulls
// it in transitively via the jwt-auth plugin, so stub it out.
jest.mock('jose', () => ({ createRemoteJWKSet: jest.fn(() => ({})), jwtVerify: jest.fn() }));

function buildApp() {
  const app = Fastify();

  app.setErrorHandler(errorHandler);

  app.get('/zod', async () => z.object({ a: z.string() }).parse({}));
  app.get('/base64', async () => {
    atob('not valid base64!!');

    return 'unreachable';
  });
  app.get('/boom', async () => {
    throw new Error('super secret internal detail');
  });
  app.get('/forbidden', async () => {
    throw Object.assign(new Error('nope'), { statusCode: 403, code: 'forbidden' });
  });

  return app;
}

describe('errorHandler', () => {
  it('maps a ZodError to 400 with a stable code', async () => {
    const response = await buildApp().inject({ method: 'GET', url: '/zod' });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ code: API_ERROR_INVALID_REQUEST });
  });

  it('maps a base64-decode error to 400', async () => {
    const response = await buildApp().inject({ method: 'GET', url: '/base64' });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ code: API_ERROR_INVALID_REQUEST });
  });

  it('returns 500 with a generic code and never leaks the underlying message', async () => {
    const response = await buildApp().inject({ method: 'GET', url: '/boom' });

    expect(response.statusCode).toBe(500);
    expect(response.json()).toEqual({ code: API_ERROR_INTERNAL });
    expect(response.body).not.toContain('super secret internal detail');
  });

  it('preserves a 4xx status and its stable code (e.g. auth errors)', async () => {
    const response = await buildApp().inject({ method: 'GET', url: '/forbidden' });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ code: 'forbidden' });
  });
});
