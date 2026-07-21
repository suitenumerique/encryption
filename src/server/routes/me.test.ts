import Fastify from 'fastify';

import { prisma } from '@encryption/src/prisma/client';
import { meRoute } from '@encryption/src/server/routes/me';

jest.mock('@encryption/src/prisma/client', () => ({
  prisma: {
    user: {
      findUnique: jest.fn(),
    },
  },
}));

const mockVerifyJWT = jest.fn();
const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

function buildApp() {
  const app = Fastify();

  app.decorate('verifyJWT', mockVerifyJWT);
  app.register(meRoute);

  return app;
}

describe('GET /api/me', () => {
  beforeEach(() => jest.clearAllMocks());

  it('returns the INTERNAL user id and email resolved by verifyJWT', async () => {
    mockVerifyJWT.mockImplementation(async (request) => {
      request.userId = 'internal-42';
    });
    (mockedPrisma.user.findUnique as jest.Mock).mockResolvedValue({ id: 'internal-42', email: 'user@example.org' });

    const response = await buildApp().inject({ method: 'GET', url: '/api/me' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ user_id: 'internal-42', email: 'user@example.org' });
    expect(mockedPrisma.user.findUnique).toHaveBeenCalledWith({ where: { id: 'internal-42' } });
  });

  it('propagates the auth failure when the token does not verify', async () => {
    mockVerifyJWT.mockRejectedValue(Object.assign(new Error('Unauthorized'), { statusCode: 401 }));

    const response = await buildApp().inject({ method: 'GET', url: '/api/me' });

    expect(response.statusCode).toBe(401);
    expect(mockedPrisma.user.findUnique).not.toHaveBeenCalled();
  });
});
