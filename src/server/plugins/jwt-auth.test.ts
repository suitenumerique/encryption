import Fastify from 'fastify';
import { jwtVerify } from 'jose';

import { env } from '@encryption/src/server/env';
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
    OIDC_ACCEPT_UNVERIFIED_EMAIL: false,
    OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION: false,
  },
}));

const mutableEnv = env as unknown as Record<string, unknown>;

const mockOidcFindUnique = jest.fn();
const mockOidcUpdate = jest.fn();
const mockOidcCreate = jest.fn();
const mockUserCreate = jest.fn();
const mockUserUpdate = jest.fn();
const mockUserFindMany = jest.fn();

jest.mock('@encryption/src/prisma/client', () => ({
  prisma: {
    oidcAccount: {
      findUnique: (...args: unknown[]) => mockOidcFindUnique(...args),
      update: (...args: unknown[]) => mockOidcUpdate(...args),
      create: (...args: unknown[]) => mockOidcCreate(...args),
    },
    user: {
      create: (...args: unknown[]) => mockUserCreate(...args),
      update: (...args: unknown[]) => mockUserUpdate(...args),
      findMany: (...args: unknown[]) => mockUserFindMany(...args),
    },
  },
}));

const mockJwtVerify = jwtVerify as jest.Mock;

// The plugin's userinfo fallback (discovery + userinfo endpoint) goes through
// global fetch; default to "network down" so only tests that opt in exercise it.
const mockFetch = jest.fn();
global.fetch = mockFetch as unknown as typeof fetch;

function jsonResponse(body: unknown, contentType = 'application/json') {
  return { ok: true, headers: { get: () => contentType }, json: async () => body, text: async () => JSON.stringify(body) };
}

/** URL-routed fetch: serves issuer discovery + a userinfo response, whatever the call order (the endpoint is cached module-wide on first success). */
function serveUserinfo(userinfoResponse: unknown) {
  mockFetch.mockImplementation(async (url: string) =>
    String(url).includes('.well-known') ? jsonResponse({ userinfo_endpoint: 'https://issuer.example/userinfo' }) : userinfoResponse
  );
}

/** A token payload that passes every boundary check unless overridden. */
function tokenPayload(overrides: Record<string, unknown> = {}) {
  return { azp: 'encryption', sub: 'user-42', email: 'user@example.org', email_verified: true, ...overrides };
}

/** A resolvable oidc_accounts row joined to its user, as the plugin reads it. */
function accountRow(overrides: Partial<{ userId: string; disabledAt: Date | null; lastSeenAt: Date; email: string }> = {}) {
  return {
    id: 'account-1',
    userId: overrides.userId ?? 'internal-1',
    disabledAt: overrides.disabledAt ?? null,
    lastSeenAt: overrides.lastSeenAt ?? new Date(),
    user: { id: overrides.userId ?? 'internal-1', email: overrides.email ?? 'user@example.org' },
  };
}

/** An email-fallback candidate with its most recent credential activity. */
function candidateRow(userId: string, lastSeenAt: Date = new Date()) {
  return { id: userId, email: 'same@example.org', oidcAccounts: [{ lastSeenAt }] };
}

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
    mockFetch.mockReset().mockRejectedValue(new Error('no network in unit tests'));
    mutableEnv.OIDC_ACCEPT_UNVERIFIED_EMAIL = false;
    mutableEnv.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = false;
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
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload() });
    mockOidcFindUnique.mockResolvedValue(accountRow());

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
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ azp: 'some-other-client' }) });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(403);
  });

  it('401s when the token has no sub (prevents an undefined userId filter)', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: undefined }) });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(401);
  });

  it('401s when sub is an empty string', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: '' }) });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(401);
  });

  it('403s at FIRST CONTACT when neither the token nor userinfo yields an email', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ email: undefined, email_verified: undefined }) });
    mockOidcFindUnique.mockResolvedValue(null);

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('email_claim_required');
    expect(mockUserCreate).not.toHaveBeenCalled();
  });

  it('403s at first contact when the email is unverified and unverified capture is off', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ email_verified: undefined }) });
    mockOidcFindUnique.mockResolvedValue(null);

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('email_claim_required');
  });

  it('authenticates a KNOWN credential even when the token carries no email claim', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ email: undefined, email_verified: undefined }) });
    mockOidcFindUnique.mockResolvedValue(accountRow({ userId: 'internal-veteran' }));

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ userId: 'internal-veteran' });
    // No email needed: no userinfo call, no stored-email refresh.
    expect(mockFetch).not.toHaveBeenCalled();
    expect(mockUserUpdate).not.toHaveBeenCalled();
  });

  it('fetches the email from the userinfo endpoint at first contact when the token lacks it', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'userinfo-newcomer', email: undefined, email_verified: undefined }) });
    mockOidcFindUnique.mockResolvedValue(null);
    mockUserCreate.mockResolvedValue({ id: 'internal-ui' });
    serveUserinfo(jsonResponse({ email: 'from-userinfo@example.org', email_verified: true }));

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(200);
    expect(mockUserCreate).toHaveBeenCalledWith({
      data: {
        email: 'from-userinfo@example.org',
        oidcAccounts: { create: { issuer: 'https://issuer.example', subject: 'userinfo-newcomer' } },
      },
    });
    // The userinfo call presents the caller's own access token.
    expect(mockFetch).toHaveBeenCalledWith('https://issuer.example/userinfo', { headers: { authorization: 'Bearer some.jwt.token' } });
  });

  it('verifies a SIGNED (application/jwt) userinfo response against the issuer JWKS (ProConnect shape)', async () => {
    // First jwtVerify call: the access token; second: the signed userinfo body.
    mockJwtVerify
      .mockResolvedValueOnce({ payload: tokenPayload({ sub: 'pc-newcomer', email: undefined, email_verified: undefined }) })
      .mockResolvedValueOnce({ payload: { email: 'signed@example.org', email_verified: true } });
    mockOidcFindUnique.mockResolvedValue(null);
    mockUserCreate.mockResolvedValue({ id: 'internal-pc' });
    serveUserinfo(jsonResponse({}, 'application/jwt'));

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(200);
    expect(mockUserCreate).toHaveBeenCalledWith({
      data: {
        email: 'signed@example.org',
        oidcAccounts: { create: { issuer: 'https://issuer.example', subject: 'pc-newcomer' } },
      },
    });
  });

  it('accepts an unverified email when the deployment opted in, but still rejects a missing one', async () => {
    mutableEnv.OIDC_ACCEPT_UNVERIFIED_EMAIL = true;

    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ email: 'unverified@example.org', email_verified: undefined, sub: 'newcomer' }) });
    mockOidcFindUnique.mockResolvedValue(null);
    mockUserCreate.mockResolvedValue({ id: 'internal-new' });

    const accepted = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(accepted.statusCode).toBe(200);
    expect(mockUserCreate).toHaveBeenCalledWith({
      data: {
        email: 'unverified@example.org',
        oidcAccounts: { create: { issuer: 'https://issuer.example', subject: 'newcomer' } },
      },
    });

    // The flag loosens VERIFICATION only, never PRESENCE.
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ email: undefined, email_verified: undefined }) });

    const rejected = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(rejected.statusCode).toBe(403);
  });

  it('resolves (issuer, sub) to the INTERNAL user id on a valid token', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload() });
    mockOidcFindUnique.mockResolvedValue(accountRow({ userId: 'internal-42' }));

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(200);
    // Never the sub: everything past the boundary speaks the internal id.
    expect(response.json()).toEqual({ userId: 'internal-42' });
    expect(mockOidcFindUnique).toHaveBeenCalledWith({
      where: { issuer_subject: { issuer: 'https://issuer.example', subject: 'user-42' } },
      include: { user: true },
    });
  });

  it('mints a User + OidcAccount on first contact', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'newcomer' }) });
    mockOidcFindUnique.mockResolvedValue(null);
    mockUserCreate.mockResolvedValue({ id: 'internal-new' });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ userId: 'internal-new' });
    expect(mockUserCreate).toHaveBeenCalledWith({
      data: {
        email: 'user@example.org',
        oidcAccounts: { create: { issuer: 'https://issuer.example', subject: 'newcomer' } },
      },
    });
  });

  it('adopts the winner row when a concurrent first request already minted the user', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'racer' }) });
    mockOidcFindUnique.mockResolvedValueOnce(null).mockResolvedValueOnce({ userId: 'internal-winner', disabledAt: null });
    mockUserCreate.mockRejectedValue(Object.assign(new Error('unique violation'), { code: 'P2002' }));

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ userId: 'internal-winner' });
  });

  it('403s (not 500) when the race winner is a retired credential', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'racer-retired' }) });
    mockOidcFindUnique.mockResolvedValueOnce(null).mockResolvedValueOnce({ userId: 'internal-winner', disabledAt: new Date() });
    mockUserCreate.mockRejectedValue(Object.assign(new Error('unique violation'), { code: 'P2002' }));

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(403);
  });

  it('403s when the credential belongs to a retired provider (disabledAt set)', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload() });
    mockOidcFindUnique.mockResolvedValue(accountRow({ disabledAt: new Date() }));

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(403);
  });

  it('refreshes the stored email when the claim changed, and only then', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ email: 'new@example.org' }) });
    mockOidcFindUnique.mockResolvedValue(accountRow({ email: 'old@example.org' }));
    mockUserUpdate.mockResolvedValue({});

    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(mockUserUpdate).toHaveBeenCalledWith({ where: { id: 'internal-1' }, data: { email: 'new@example.org' } });

    // Same email: no write.
    mockUserUpdate.mockClear();
    mockOidcFindUnique.mockResolvedValue(accountRow({ email: 'new@example.org' }));
    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });
    expect(mockUserUpdate).not.toHaveBeenCalled();
  });

  it('links an unknown credential to the single user holding its VERIFIED email when the fallback flag is on', async () => {
    mutableEnv.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = true;
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'new-sub-after-migration', email: 'same@example.org' }) });
    mockOidcFindUnique.mockResolvedValue(null);
    mockUserFindMany.mockResolvedValue([candidateRow('internal-existing')]);
    mockOidcCreate.mockResolvedValue({ userId: 'internal-existing' });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.json()).toEqual({ userId: 'internal-existing' });
    expect(mockOidcCreate).toHaveBeenCalledWith({
      data: { userId: 'internal-existing', issuer: 'https://issuer.example', subject: 'new-sub-after-migration' },
    });
    expect(mockUserCreate).not.toHaveBeenCalled();
  });

  it('mints a fresh user instead of linking when the email is ambiguous (several users hold it)', async () => {
    mutableEnv.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = true;
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'ambiguous', email: 'shared@example.org' }) });
    mockOidcFindUnique.mockResolvedValue(null);
    mockUserFindMany.mockResolvedValue([candidateRow('internal-a'), candidateRow('internal-b')]);
    mockUserCreate.mockResolvedValue({ id: 'internal-fresh' });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.json()).toEqual({ userId: 'internal-fresh' });
    expect(mockOidcCreate).not.toHaveBeenCalled();
  });

  it('mints a fresh user instead of linking when the sole match has been dormant for over a year', async () => {
    // Recycled-address guard: a provider migration links people who are still
    // around; a year-dormant account more likely means the address now belongs
    // to a different human.
    mutableEnv.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = true;
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'late-comer', email: 'same@example.org' }) });
    mockOidcFindUnique.mockResolvedValue(null);
    mockUserFindMany.mockResolvedValue([candidateRow('internal-dormant', new Date(Date.now() - 400 * 24 * 60 * 60 * 1000))]);
    mockUserCreate.mockResolvedValue({ id: 'internal-fresh' });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.json()).toEqual({ userId: 'internal-fresh' });
    expect(mockOidcCreate).not.toHaveBeenCalled();
  });

  it('never links by email when the fallback flag is off, or when the email is unverified', async () => {
    // Flag off: no candidate lookup at all.
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'no-fallback', email: 'a@example.org' }) });
    mockOidcFindUnique.mockResolvedValue(null);
    mockUserCreate.mockResolvedValue({ id: 'internal-x' });
    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });
    expect(mockUserFindMany).not.toHaveBeenCalled();

    // Flag on but unverified email: still no linking (capture opt-in does NOT
    // weaken identification), even though the address is captured.
    mutableEnv.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = true;
    mutableEnv.OIDC_ACCEPT_UNVERIFIED_EMAIL = true;
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'unverified-sub', email: 'b@example.org', email_verified: undefined }) });
    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });
    expect(mockUserFindMany).not.toHaveBeenCalled();
  });

  it('bumps lastSeenAt only when it is older than the daily throttle', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload() });

    // Fresh row: no write.
    mockOidcFindUnique.mockResolvedValue(accountRow({ lastSeenAt: new Date() }));
    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });
    expect(mockOidcUpdate).not.toHaveBeenCalled();

    // Stale row (two days old): one write.
    mockOidcFindUnique.mockResolvedValue(accountRow({ lastSeenAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000) }));
    mockOidcUpdate.mockResolvedValue({});
    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });
    expect(mockOidcUpdate).toHaveBeenCalledWith({ where: { id: 'account-1' }, data: { lastSeenAt: expect.any(Date) } });
  });
});
