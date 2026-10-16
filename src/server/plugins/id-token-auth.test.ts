import Fastify from 'fastify';
import { type CryptoKey, type JWK, SignJWT, exportJWK, generateKeyPair } from 'jose';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { testPrisma, useTestDatabase } from '@encryption/src/prisma/testing';
import { resetProviderCache } from '@encryption/src/server/auth/oidc-provider';
import { idTokenAuthPlugin } from '@encryption/src/server/plugins/id-token-auth';

const ISSUER = 'https://issuer.example/realms/suite';

vi.mock('@encryption/src/prisma/client', async () => ({
  prisma: (await vi.importActual<typeof import('@encryption/src/prisma/testing')>('@encryption/src/prisma/testing')).testPrisma,
}));

vi.mock('@encryption/src/server/env', () => ({
  env: {
    OIDC_ISSUER: 'https://issuer.example/realms/suite',
    OIDC_CLIENT_ID: 'encryption',
  },
}));

let providerKey: CryptoKey;
let publicJwk: JWK;
let fetchSpy: ReturnType<typeof vi.fn>;

async function idToken(claims: Record<string, unknown>, options: { audience?: string; expiresAt?: number | string } = {}) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256', kid: 'provider-key' })
    .setIssuer(ISSUER)
    .setAudience(options.audience ?? 'encryption')
    .setIssuedAt()
    .setExpirationTime(options.expiresAt ?? '1h')
    .sign(providerKey);
}

function buildApp() {
  const app = Fastify();

  app.register(idTokenAuthPlugin);
  app.get('/protected', { preHandler: async (request) => app.verifyIdToken(request) }, async (request) => ({
    userId: request.userId,
    acr: request.idTokenClaims?.acr ?? null,
  }));

  return app;
}

async function signedUpUser(subject = 'user-42'): Promise<{ userId: string; accountId: string }> {
  const user = await testPrisma.user.create({ data: { email: 'user@example.org' } });
  const account = await testPrisma.oidcAccount.create({ data: { userId: user.id, issuer: ISSUER, subject } });

  return { userId: user.id, accountId: account.id };
}

function call(token: string) {
  return buildApp().inject({ method: 'GET', url: '/protected', headers: { authorization: `Bearer ${token}` } });
}

beforeAll(async () => {
  const pair = await generateKeyPair('ES256', { extractable: true });

  publicJwk = { ...(await exportJWK(pair.publicKey)), kid: 'provider-key', alg: 'ES256', use: 'sig' };
  providerKey = pair.privateKey;
});

beforeEach(() => {
  resetProviderCache();
  const provider: Record<string, unknown> = {
    [`${ISSUER}/.well-known/openid-configuration`]: {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/auth`,
      token_endpoint: `${ISSUER}/token`,
      jwks_uri: `${ISSUER}/certs`,
    },
    [`${ISSUER}/certs`]: { keys: [publicJwk] },
  };

  fetchSpy = vi.fn(async (input: string | URL) => {
    const body = provider[String(input)];

    return body ? Response.json(body) : new Response('not found', { status: 404 });
  });
  vi.stubGlobal('fetch', fetchSpy);
});

describe('idTokenAuthPlugin', () => {
  useTestDatabase();

  it('authenticates an ID token issued to our client as its INTERNAL user id, exposing its claims', async () => {
    const { userId } = await signedUpUser();

    const response = await call(await idToken({ sub: 'user-42', acr: 'eidas1' }));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ userId, acr: 'eidas1' });
  });

  it('verifies locally: the discovery document and the keys are fetched once, never the provider per request', async () => {
    await signedUpUser();
    const app = buildApp();
    const token = await idToken({ sub: 'user-42' });

    for (let i = 0; i < 3; i++) {
      expect((await app.inject({ method: 'GET', url: '/protected', headers: { authorization: `Bearer ${token}` } })).statusCode).toBe(200);
    }

    expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual([`${ISSUER}/.well-known/openid-configuration`, `${ISSUER}/certs`]);
  });

  it('401s when the Authorization header is missing or not a Bearer token', async () => {
    const missing = await buildApp().inject({ method: 'GET', url: '/protected' });
    const basic = await buildApp().inject({ method: 'GET', url: '/protected', headers: { authorization: 'Basic abc' } });

    expect(missing.statusCode).toBe(401);
    expect(basic.statusCode).toBe(401);
    expect(missing.json().code).toBe('unauthorized');
  });

  it.each([
    ['an ID token issued to another product', () => idToken({ sub: 'user-42' }, { audience: 'docs' })],
    ['an expired ID token', () => idToken({ sub: 'user-42' }, { expiresAt: Math.floor(Date.now() / 1000) - 120 })],
    ['an opaque access token', async () => 'opaque-access-token'],
  ])('401s on %s', async (_label, makeToken) => {
    await signedUpUser();

    const response = await call(await makeToken());

    expect(response.statusCode).toBe(401);
    expect(response.json().code).toBe('unauthorized');
  });

  it('401s on a valid ID token whose user never signed in through our login', async () => {
    const response = await call(await idToken({ sub: 'stranger' }));

    expect(response.statusCode).toBe(401);
  });

  it('403s (not 401) once the credential is retired', async () => {
    const { accountId } = await signedUpUser();

    await testPrisma.oidcAccount.update({ where: { id: accountId }, data: { disabledAt: new Date() } });

    const response = await call(await idToken({ sub: 'user-42' }));

    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('forbidden');
  });
});
