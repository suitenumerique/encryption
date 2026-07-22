import Fastify from 'fastify';

import { testPrisma, useTestDatabase } from '@encryption/src/prisma/testing';
import { meRoute } from '@encryption/src/server/routes/me';

jest.mock('@encryption/src/prisma/client', () => ({ prisma: jest.requireActual('@encryption/src/prisma/testing').testPrisma }));

const mockVerifyJWT = jest.fn();

function buildApp() {
  const app = Fastify();

  app.decorate('verifyJWT', mockVerifyJWT);
  app.register(meRoute);

  return app;
}

describe('GET /api/me', () => {
  useTestDatabase();

  beforeEach(() => jest.clearAllMocks());

  it('returns the INTERNAL user id and email resolved by verifyJWT', async () => {
    const user = await testPrisma.user.create({ data: { email: 'user@example.org' } });

    mockVerifyJWT.mockImplementation(async (request) => {
      request.userId = user.id;
    });

    const response = await buildApp().inject({ method: 'GET', url: '/api/me' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ user_id: user.id, email: 'user@example.org' });
  });

  it('answers with a null email when the token resolves to a user that no longer exists', async () => {
    mockVerifyJWT.mockImplementation(async (request) => {
      request.userId = '00000000-0000-4000-8000-000000000000';
    });

    const response = await buildApp().inject({ method: 'GET', url: '/api/me' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ user_id: '00000000-0000-4000-8000-000000000000', email: null });
  });

  it('propagates the auth failure when the token does not verify', async () => {
    mockVerifyJWT.mockRejectedValue(Object.assign(new Error('Unauthorized'), { statusCode: 401 }));

    const response = await buildApp().inject({ method: 'GET', url: '/api/me' });

    expect(response.statusCode).toBe(401);
  });
});
