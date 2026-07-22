import Fastify from 'fastify';
import { jwtVerify } from 'jose';

import { testPrisma, testPrismaClient, useTestDatabase } from '@encryption/src/prisma/testing';
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

jest.mock('@encryption/src/prisma/client', () => ({ prisma: jest.requireActual('@encryption/src/prisma/testing').testPrisma }));

const mutableEnv = env as unknown as Record<string, unknown>;

const mockJwtVerify = jwtVerify as jest.Mock;

// The plugin's userinfo fallback (discovery + userinfo endpoint) goes through
// global fetch; default to "network down" so only tests that opt in exercise it.
const mockFetch = jest.fn();
global.fetch = mockFetch as unknown as typeof fetch;

const ISSUER = 'https://issuer.example';

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

/** A user with one credential for (ISSUER, subject), as an already-known caller. */
async function seedAccount(
  overrides: Partial<{ subject: string; email: string; disabledAt: Date | null; lastSeenAt: Date }> = {}
): Promise<{ userId: string; accountId: string }> {
  const user = await testPrisma.user.create({ data: { email: overrides.email ?? 'user@example.org' } });
  const account = await testPrisma.oidcAccount.create({
    data: {
      userId: user.id,
      issuer: ISSUER,
      subject: overrides.subject ?? 'user-42',
      disabledAt: overrides.disabledAt ?? null,
      lastSeenAt: overrides.lastSeenAt ?? new Date(),
    },
  });

  return { userId: user.id, accountId: account.id };
}

/** An email-fallback candidate: a user whose only credential was last seen at the given date. */
async function seedCandidate(email: string, lastSeenAt: Date = new Date()): Promise<string> {
  const user = await testPrisma.user.create({ data: { email } });

  await testPrisma.oidcAccount.create({
    data: { userId: user.id, issuer: ISSUER, subject: `old-sub-${user.id}`, lastSeenAt },
  });

  return user.id;
}

function buildApp() {
  const app = Fastify();

  app.register(jwtAuthPlugin);
  app.get('/protected', { preHandler: async (request) => app.verifyJWT(request) }, async (request) => ({ userId: request.userId }));

  return app;
}

const BEARER = { authorization: 'Bearer some.jwt.token' };

describe('jwtAuthPlugin', () => {
  useTestDatabase();

  beforeEach(() => {
    jest.restoreAllMocks();
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
    await seedAccount();
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload() });

    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(mockJwtVerify).toHaveBeenCalledWith('some.jwt.token', expect.anything(), { issuer: ISSUER });
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

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('email_claim_required');
    expect(await testPrisma.user.count()).toBe(0);
  });

  it('403s at first contact when the email is unverified and unverified capture is off', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ email_verified: undefined }) });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(403);
    expect(response.json().code).toBe('email_claim_required');
    expect(await testPrisma.user.count()).toBe(0);
  });

  it('authenticates a KNOWN credential even when the token carries no email claim', async () => {
    const { userId } = await seedAccount({ subject: 'veteran' });

    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'veteran', email: undefined, email_verified: undefined }) });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ userId });
    // No email needed: no userinfo call, and the stored address is untouched.
    expect(mockFetch).not.toHaveBeenCalled();
    expect((await testPrisma.user.findUniqueOrThrow({ where: { id: userId } })).email).toBe('user@example.org');
  });

  it('fetches the email from the userinfo endpoint at first contact when the token lacks it', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'userinfo-newcomer', email: undefined, email_verified: undefined }) });
    serveUserinfo(jsonResponse({ email: 'from-userinfo@example.org', email_verified: true }));

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(200);

    const minted = await testPrisma.user.findFirstOrThrow({ include: { oidcAccounts: true } });

    expect(minted.email).toBe('from-userinfo@example.org');
    expect(minted.oidcAccounts).toHaveLength(1);
    expect(minted.oidcAccounts[0]).toMatchObject({ issuer: ISSUER, subject: 'userinfo-newcomer' });
    // The userinfo call presents the caller's own access token.
    expect(mockFetch).toHaveBeenCalledWith('https://issuer.example/userinfo', { headers: { authorization: 'Bearer some.jwt.token' } });
  });

  it('verifies a SIGNED (application/jwt) userinfo response against the issuer JWKS (ProConnect shape)', async () => {
    // First jwtVerify call: the access token; second: the signed userinfo body.
    mockJwtVerify
      .mockResolvedValueOnce({ payload: tokenPayload({ sub: 'pc-newcomer', email: undefined, email_verified: undefined }) })
      .mockResolvedValueOnce({ payload: { email: 'signed@example.org', email_verified: true } });
    serveUserinfo(jsonResponse({}, 'application/jwt'));

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(200);

    const minted = await testPrisma.user.findFirstOrThrow({ include: { oidcAccounts: true } });

    expect(minted.email).toBe('signed@example.org');
    expect(minted.oidcAccounts[0]).toMatchObject({ issuer: ISSUER, subject: 'pc-newcomer' });
  });

  it('accepts an unverified email when the deployment opted in, but still rejects a missing one', async () => {
    mutableEnv.OIDC_ACCEPT_UNVERIFIED_EMAIL = true;

    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ email: 'unverified@example.org', email_verified: undefined, sub: 'newcomer' }) });

    const accepted = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(accepted.statusCode).toBe(200);

    const minted = await testPrisma.user.findFirstOrThrow({ include: { oidcAccounts: true } });

    expect(minted.email).toBe('unverified@example.org');
    expect(minted.oidcAccounts[0]).toMatchObject({ issuer: ISSUER, subject: 'newcomer' });

    // The flag loosens VERIFICATION only, never PRESENCE.
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'no-email-at-all', email: undefined, email_verified: undefined }) });

    const rejected = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(rejected.statusCode).toBe(403);
    expect(await testPrisma.user.count()).toBe(1);
  });

  it('resolves (issuer, sub) to the INTERNAL user id on a valid token', async () => {
    const { userId } = await seedAccount();

    mockJwtVerify.mockResolvedValue({ payload: tokenPayload() });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(200);
    // Never the sub: everything past the boundary speaks the internal id.
    expect(response.json()).toEqual({ userId });
    expect(userId).not.toBe('user-42');
  });

  it('mints a User + OidcAccount on first contact', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'newcomer' }) });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(200);

    const minted = await testPrisma.user.findFirstOrThrow({ include: { oidcAccounts: true } });

    expect(response.json()).toEqual({ userId: minted.id });
    expect(minted.email).toBe('user@example.org');
    expect(minted.oidcAccounts).toHaveLength(1);
    expect(minted.oidcAccounts[0]).toMatchObject({ issuer: ISSUER, subject: 'newcomer' });
  });

  it('adopts the winner row when a concurrent first request already minted the user', async () => {
    // The interleaving (row absent at lookup, present at insert) is produced
    // deterministically from one session: the in-process Postgres has a single
    // backend, so a genuinely concurrent request cannot be run against it, but
    // the unique violation the plugin recovers from is the real one raised by
    // the (issuer, subject) constraint.
    const winner = await seedAccount({ subject: 'racer', email: 'winner@example.org' });

    // Only the FIRST lookup misses; the spy calls through afterwards, so the
    // recovery path reads the winner from the database like it would in life.
    jest.spyOn(testPrismaClient().oidcAccount, 'findUnique').mockImplementationOnce((async () => null) as never);

    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'racer' }) });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ userId: winner.userId });
    // The losing insert left nothing behind.
    expect(await testPrisma.user.count()).toBe(1);
  });

  it('403s (not 500) when the race winner is a retired credential', async () => {
    await seedAccount({ subject: 'racer-retired', disabledAt: new Date() });

    jest.spyOn(testPrismaClient().oidcAccount, 'findUnique').mockImplementationOnce((async () => null) as never);

    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'racer-retired' }) });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(403);
  });

  it('403s when the credential belongs to a retired provider (disabledAt set)', async () => {
    await seedAccount({ disabledAt: new Date() });

    mockJwtVerify.mockResolvedValue({ payload: tokenPayload() });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.statusCode).toBe(403);
  });

  it('refreshes the stored email when the claim changed, and only then', async () => {
    const { userId } = await seedAccount({ email: 'old@example.org' });

    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ email: 'new@example.org' }) });

    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    const refreshed = await testPrisma.user.findUniqueOrThrow({ where: { id: userId } });

    expect(refreshed.email).toBe('new@example.org');

    // Same email: no write, so updatedAt does not move.
    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    const untouched = await testPrisma.user.findUniqueOrThrow({ where: { id: userId } });

    expect(untouched.updatedAt).toEqual(refreshed.updatedAt);
  });

  it('links an unknown credential to the single user holding its VERIFIED email when the fallback flag is on', async () => {
    mutableEnv.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = true;

    const existingUserId = await seedCandidate('same@example.org');

    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'new-sub-after-migration', email: 'same@example.org' }) });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.json()).toEqual({ userId: existingUserId });
    // The new credential joined the SAME user, no second user was minted.
    expect(await testPrisma.user.count()).toBe(1);
    expect(await testPrisma.oidcAccount.count({ where: { userId: existingUserId } })).toBe(2);
    expect(await testPrisma.oidcAccount.findFirstOrThrow({ where: { subject: 'new-sub-after-migration' } })).toMatchObject({
      userId: existingUserId,
      issuer: ISSUER,
    });
  });

  it('mints a fresh user instead of linking when the email is ambiguous (several users hold it)', async () => {
    mutableEnv.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = true;

    const first = await seedCandidate('shared@example.org');
    const second = await seedCandidate('shared@example.org');

    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'ambiguous', email: 'shared@example.org' }) });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect([first, second]).not.toContain(response.json().userId);
    expect(await testPrisma.user.count()).toBe(3);
  });

  it('mints a fresh user instead of linking when the sole match has been dormant for over a year', async () => {
    // Recycled-address guard: a provider migration links people who are still
    // around; a year-dormant account more likely means the address now belongs
    // to a different human.
    mutableEnv.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = true;

    const dormantUserId = await seedCandidate('same@example.org', new Date(Date.now() - 400 * 24 * 60 * 60 * 1000));

    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'late-comer', email: 'same@example.org' }) });

    const response = await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(response.json().userId).not.toBe(dormantUserId);
    expect(await testPrisma.user.count()).toBe(2);
    expect(await testPrisma.oidcAccount.count({ where: { userId: dormantUserId } })).toBe(1);
  });

  it('never links by email when the fallback flag is off, or when the email is unverified', async () => {
    // Flag off: the holder of the address keeps it to itself.
    const holderId = await seedCandidate('a@example.org');

    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'no-fallback', email: 'a@example.org' }) });
    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(await testPrisma.oidcAccount.count({ where: { userId: holderId } })).toBe(1);

    // Flag on but unverified email: still no linking (capture opt-in does NOT
    // weaken identification), even though the address is captured.
    mutableEnv.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = true;
    mutableEnv.OIDC_ACCEPT_UNVERIFIED_EMAIL = true;

    const secondHolderId = await seedCandidate('b@example.org');

    mockJwtVerify.mockResolvedValue({ payload: tokenPayload({ sub: 'unverified-sub', email: 'b@example.org', email_verified: undefined }) });
    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect(await testPrisma.oidcAccount.count({ where: { userId: secondHolderId } })).toBe(1);
  });

  it('bumps lastSeenAt only when it is older than the daily throttle', async () => {
    mockJwtVerify.mockResolvedValue({ payload: tokenPayload() });

    // Fresh row: no write.
    const fresh = await seedAccount({ lastSeenAt: new Date() });
    const freshBefore = await testPrisma.oidcAccount.findUniqueOrThrow({ where: { id: fresh.accountId } });

    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    expect((await testPrisma.oidcAccount.findUniqueOrThrow({ where: { id: fresh.accountId } })).lastSeenAt).toEqual(freshBefore.lastSeenAt);

    // Stale row (two days old): one write.
    await emptyForNextCase();

    const stale = await seedAccount({ lastSeenAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000) });

    await buildApp().inject({ method: 'GET', url: '/protected', headers: BEARER });

    const bumped = await testPrisma.oidcAccount.findUniqueOrThrow({ where: { id: stale.accountId } });

    expect(bumped.lastSeenAt.getTime()).toBeGreaterThan(Date.now() - 60000);
  });
});

/** Clears the rows of the current test so a second case can seed from scratch. */
async function emptyForNextCase(): Promise<void> {
  await testPrisma.oidcAccount.deleteMany({});
  await testPrisma.user.deleteMany({});
}
