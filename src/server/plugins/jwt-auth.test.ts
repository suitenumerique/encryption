import Fastify from 'fastify';
import { jwtVerify } from 'jose';

import { jwtAuthPlugin } from '@encryption/src/server/plugins/jwt-auth';

// jose is mocked so the plugin's control flow (issuer/azp/sub checks) is tested
// without a real JWKS fetch or signature verification.
jest.mock('jose', () => ({
  createRemoteJWKSet: jest.fn(() => ({})),
  jwtVerify: jest.fn(),
}));

// env is mocked so importing the plugin does not pull the real env validator
// (which would exit the process when the vars are absent under test).
jest.mock('@encryption/src/server/env', () => ({
  env: {
    OIDC_JWKS_URL: 'https://issuer.example/.well-known/jwks.json',
    OIDC_ISSUER: 'https://issuer.example',
    OIDC_SERVER_CLIENT_ID: 'encryption',
  },
}));

const mockJwtVerify = jwtVerify as jest.Mock;

function buildApp() {
  const app = Fastify();

  app.register(jwtAuthPlugin);
  app.get('/protected', { preHandler: async (request) => app.verifyJWT(request) }, async (request) => ({ userId: request.userId }));

  return app;
}

const BEARER = { authorization: 'Bearer some.jwt.token' };

describe('jwtAuthPlugin', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('401s when the Authorization header is missing', async () => {
    const response = await buildApp().inject({ method: 'GET', url: '/protected' });

    expect(response.statusCode).toBe(401);
    expect(mockJwtVerify).not.toHaveBeenCalled();
  });

  it('401s when the Authorization header is not a Bearer token', async () => {
    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: { authorization: 'Basic abc' } });

    expect(response.statusCode).toBe(401);
  });

  it('passes the configured issuer to jwtVerify', async () => {
    mockJwtVerify.mockResolvedValue({ payload: { azp: 'encryption', sub: 'user-1' } });

    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(mockJwtVerify).toHaveBeenCalledWith('some.jwt.token', expect.anything(), { issuer: 'https://issuer.example' });
  });

  it('401s when the token fails verification (bad signature / expiry / issuer)', async () => {
    mockJwtVerify.mockRejectedValue(new Error('signature verification failed'));

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(401);
  });

  it('403s (not 401) when the token was issued for another client (wrong azp)', async () => {
    // Regression: the azp check used to live inside the try, so its 403 was
    // swallowed and remapped to 401 by the catch. It must surface as 403.
    mockJwtVerify.mockResolvedValue({ payload: { azp: 'some-other-client', sub: 'user-1' } });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(403);
  });

  it('401s when the token has no sub (prevents an undefined userId filter)', async () => {
    mockJwtVerify.mockResolvedValue({ payload: { azp: 'encryption' } });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(401);
  });

  it('401s when sub is an empty string', async () => {
    mockJwtVerify.mockResolvedValue({ payload: { azp: 'encryption', sub: '' } });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(401);
  });

  it('sets request.userId from sub on a valid token', async () => {
    mockJwtVerify.mockResolvedValue({ payload: { azp: 'encryption', sub: 'user-42' } });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ userId: 'user-42' });
  });
});
