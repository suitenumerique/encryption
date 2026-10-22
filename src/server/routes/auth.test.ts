import Fastify, { type FastifyInstance } from 'fastify';
import { type Mock, afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { testPrisma, useTestDatabase } from '@encryption/src/prisma/testing';
import {
  IdTokenError,
  OidcLoginError,
  buildAuthorizationUrl,
  exchangeCode,
  fetchUserinfo,
  verifyIdToken,
} from '@encryption/src/server/auth/oidc-provider';
import { env } from '@encryption/src/server/env';
import { idTokenAuthPlugin } from '@encryption/src/server/plugins/id-token-auth';
import { authRoute } from '@encryption/src/server/routes/auth';
import { createTestApiClient } from '@encryption/src/server/testing/inject-client';
import { postApiAuthToken } from '@encryption/src/ui/api/generated/sdk.gen';

// The provider is faked at the module boundary: its own behaviour (signatures,
// userinfo shapes) is covered by oidc-provider.test.ts. Here: what the login
// does with what the provider says.
vi.mock('@encryption/src/server/auth/oidc-provider', async (importActual) => {
  const actual = await importActual<typeof import('@encryption/src/server/auth/oidc-provider')>();

  return {
    OidcLoginError: actual.OidcLoginError,
    IdTokenError: actual.IdTokenError,
    buildAuthorizationUrl: vi.fn(),
    exchangeCode: vi.fn(),
    verifyIdToken: vi.fn(),
    fetchUserinfo: vi.fn(),
  };
});

vi.mock('@encryption/src/server/env', () => ({
  env: {
    OIDC_ISSUER: 'https://issuer.example',
    OIDC_ACCEPT_UNVERIFIED_EMAIL: false,
    OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION: false,
    OIDC_STEP_UP_ACR_VALUES: ['eidas1-mfa'],
    OIDC_STEP_UP_AMR_VALUES: ['mfa'],
    OIDC_CLAIMS_FIRST_NAME: ['given_name'],
    OIDC_CLAIMS_LAST_NAME: ['usual_name', 'family_name'],
    OIDC_CLAIMS_FULL_NAME: ['name'],
  },
}));

vi.mock('@encryption/src/prisma/client', async () => ({
  prisma: (await vi.importActual<typeof import('@encryption/src/prisma/testing')>('@encryption/src/prisma/testing')).testPrisma,
}));

const ISSUER = 'https://issuer.example';
const mutableEnv = env as unknown as Record<string, unknown>;

const PKCE_VERIFIER = 'v'.repeat(43);
const NONCE = 'n'.repeat(32);
const LOGIN = { code: 'the-code', code_verifier: PKCE_VERIFIER, nonce: NONCE };

const ID_TOKEN_EXP = Math.floor(Date.now() / 1000) + 3600;

const NAMES = { given_name: 'Alice', usual_name: 'Martin' };

/**
 * The provider vouching for `sub`, with these claims in the ID token and, in
 * userinfo, the names plus whatever is given (the usual shape: a bare ID
 * token, everything personal in userinfo).
 */
function providerSays(idClaims: Record<string, unknown>, more: { userinfo?: Record<string, unknown> } = {}) {
  (exchangeCode as Mock).mockResolvedValue({ idToken: 'the.id.token', accessToken: 'opaque-access-token' });
  (verifyIdToken as Mock).mockResolvedValue({ sub: 'user-42', exp: ID_TOKEN_EXP, ...idClaims });
  (fetchUserinfo as Mock).mockResolvedValue({ ...NAMES, ...more.userinfo });
}

const VERIFIED = { email: 'user@example.org', email_verified: true };

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

  await testPrisma.oidcAccount.create({ data: { userId: user.id, issuer: ISSUER, subject: `old-sub-${user.id}`, lastSeenAt } });

  return user.id;
}

describe('auth routes', () => {
  useTestDatabase();

  let app: FastifyInstance;
  let client: ReturnType<typeof createTestApiClient>;

  beforeAll(async () => {
    app = Fastify();
    app.register(idTokenAuthPlugin);
    app.register(authRoute);
    await app.ready();

    client = createTestApiClient(app);
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    mutableEnv.OIDC_ACCEPT_UNVERIFIED_EMAIL = false;
    mutableEnv.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = false;
  });

  const login = (body: Partial<typeof LOGIN> & { expected_sub?: string; language?: 'fr' | 'en' } = {}) =>
    postApiAuthToken({ client, body: { ...LOGIN, ...body } });

  describe('GET /api/auth/authorize', () => {
    it('redirects the login tab to the provider with what the tab generated', async () => {
      (buildAuthorizationUrl as Mock).mockResolvedValue('https://issuer.example/auth?x=1');

      const query = `state=${'s'.repeat(43)}&nonce=${NONCE}&code_challenge=${'c'.repeat(43)}&prompt=login`;
      const response = await app.inject({ method: 'GET', url: `/api/auth/authorize?${query}` });

      expect(response.statusCode).toBe(302);
      expect(response.headers.location).toBe('https://issuer.example/auth?x=1');
      expect(buildAuthorizationUrl).toHaveBeenCalledWith({
        state: 's'.repeat(43),
        nonce: NONCE,
        codeChallenge: 'c'.repeat(43),
        prompt: 'login',
        stepUp: false,
      });
    });

    it('passes a step-up request on to the provider URL', async () => {
      (buildAuthorizationUrl as Mock).mockResolvedValue('https://issuer.example/auth?x=1');

      const query = `state=${'s'.repeat(43)}&nonce=${NONCE}&code_challenge=${'c'.repeat(43)}&step_up=1`;

      expect((await app.inject({ method: 'GET', url: `/api/auth/authorize?${query}` })).statusCode).toBe(302);
      expect(buildAuthorizationUrl).toHaveBeenCalledWith(expect.objectContaining({ stepUp: true }));
    });

    it("passes the interface's language on to the provider URL, and only a supported one", async () => {
      (buildAuthorizationUrl as Mock).mockResolvedValue('https://issuer.example/auth?x=1');

      const query = `state=${'s'.repeat(43)}&nonce=${NONCE}&code_challenge=${'c'.repeat(43)}`;

      expect((await app.inject({ method: 'GET', url: `/api/auth/authorize?${query}&ui_locales=fr` })).statusCode).toBe(302);
      expect(buildAuthorizationUrl).toHaveBeenCalledWith(expect.objectContaining({ uiLocale: 'fr' }));
      expect((await app.inject({ method: 'GET', url: `/api/auth/authorize?${query}&ui_locales=de` })).statusCode).toBe(400);
    });

    it('refuses a request without a PKCE challenge or with a weak state', async () => {
      const noChallenge = await app.inject({ method: 'GET', url: `/api/auth/authorize?state=${'s'.repeat(43)}&nonce=${NONCE}` });
      const weakState = await app.inject({ method: 'GET', url: `/api/auth/authorize?state=abc&nonce=${NONCE}&code_challenge=${'c'.repeat(43)}` });

      expect(noChallenge.statusCode).toBe(400);
      expect(weakState.statusCode).toBe(400);
      expect(buildAuthorizationUrl).not.toHaveBeenCalled();
    });
  });

  describe('POST /api/auth/token', () => {
    it('exchanges the code, verifies the ID token against the nonce, and hands the ID token back with who it is for', async () => {
      providerSays({ acr: 'eidas1' }, { userinfo: { ...VERIFIED, locale: 'fr-FR' } });

      const { data, response } = await login();

      expect(response?.status).toBe(200);
      expect(exchangeCode).toHaveBeenCalledWith('the-code', PKCE_VERIFIER);
      expect(verifyIdToken).toHaveBeenCalledWith('the.id.token', { nonce: NONCE });
      expect(fetchUserinfo).toHaveBeenCalledWith('opaque-access-token', 'user-42');

      const account = await testPrisma.oidcAccount.findUniqueOrThrow({ where: { issuer_subject: { issuer: ISSUER, subject: 'user-42' } } });

      expect(data).toEqual({
        id_token: 'the.id.token',
        expires_at: new Date(ID_TOKEN_EXP * 1000).toISOString(),
        sub: 'user-42',
        user_id: account.userId,
        email: 'user@example.org',
        first_name: 'Alice',
        last_name: 'Martin',
        second_factor: false,
      });
      expect(await testPrisma.user.findUniqueOrThrow({ where: { id: account.userId } })).toMatchObject({ email: 'user@example.org', language: 'fr' });
    });

    it('never answers with the access token', async () => {
      providerSays({}, { userinfo: VERIFIED });

      const { data } = await login();

      expect(JSON.stringify(data)).not.toContain('opaque-access-token');
    });

    it('reports a login the provider says used a second factor', async () => {
      providerSays({ acr: 'eidas1-mfa' }, { userinfo: VERIFIED });

      expect((await login()).data?.second_factor).toBe(true);
    });

    it('still takes the email from the ID token when a provider put it there', async () => {
      providerSays(VERIFIED);

      expect((await login()).data?.email).toBe('user@example.org');
    });

    it('does not call userinfo when the ID token already carries the email, the names and the locale', async () => {
      providerSays({ ...VERIFIED, given_name: 'Jean', family_name: 'Dupont', locale: 'fr' });

      const { data } = await login();

      expect(fetchUserinfo).not.toHaveBeenCalled();
      expect(data).toMatchObject({ email: 'user@example.org', first_name: 'Jean', last_name: 'Dupont' });
    });

    it('asks userinfo for a locale the ID token lacks, though nothing required is missing', async () => {
      providerSays({ ...VERIFIED, given_name: 'Jean', family_name: 'Dupont' }, { userinfo: { locale: 'fr-FR' } });

      const { data } = await login();

      expect(fetchUserinfo).toHaveBeenCalled();
      expect(await testPrisma.user.findUniqueOrThrow({ where: { id: data!.user_id } })).toMatchObject({ language: 'fr' });
    });

    it('derives the last name from the full name when the provider gives none', async () => {
      providerSays({});
      (fetchUserinfo as Mock).mockResolvedValue({ ...VERIFIED, given_name: 'Jean', name: 'Jean Dupont' });

      expect((await login()).data).toMatchObject({ first_name: 'Jean', last_name: 'Dupont' });
    });

    it('403s with name_claims_required, minting nobody, when the first name or any last name is missing', async () => {
      for (const userinfo of [
        { ...VERIFIED, usual_name: 'Martin' },
        { ...VERIFIED, given_name: 'Alice' },
      ]) {
        providerSays({});
        (fetchUserinfo as Mock).mockResolvedValue(userinfo);

        const { error, response } = await login();

        expect(response?.status).toBe(403);
        expect(error).toMatchObject({ code: 'name_claims_required' });
      }

      expect(await testPrisma.user.count()).toBe(0);
    });

    it("never pairs one source's address with another source's verification flag", async () => {
      // An unverified address in the ID token, a verified flag (for another
      // address) in userinfo: the ID token's address stays unverified.
      providerSays({ email: 'unverified@example.org' }, { userinfo: { email: 'other@example.org', email_verified: true } });

      const { error, response } = await login();

      expect(response?.status).toBe(403);
      expect(error).toMatchObject({ code: 'email_claim_required' });
    });

    it('401s with oidc_login_failed whenever the provider does not vouch, and mints nothing', async () => {
      for (const fail of [
        () => (exchangeCode as Mock).mockRejectedValue(new OidcLoginError('token endpoint answered 400 (invalid_grant)')),
        () => (verifyIdToken as Mock).mockRejectedValue(new IdTokenError('ID token nonce does not match the login')),
      ]) {
        providerSays(VERIFIED);
        fail();

        const { error, response } = await login();

        expect(response?.status).toBe(401);
        expect(error).toMatchObject({ code: 'oidc_login_failed' });
      }

      expect(await testPrisma.user.count()).toBe(0);
    });

    it('answers 500, not 401, on a fault of ours (provider unreachable is not a refused login)', async () => {
      providerSays(VERIFIED);
      (exchangeCode as Mock).mockRejectedValue(new Error('OIDC discovery failed: 503'));

      const { response } = await login();

      expect(response?.status).toBe(500);
    });

    it('refuses a login as someone other than the expected user BEFORE resolving or minting anything', async () => {
      providerSays({ ...VERIFIED, sub: 'someone-else' });

      const { error, response } = await login({ expected_sub: 'user-42' });

      expect(response?.status).toBe(409);
      expect(error).toMatchObject({ code: 'wrong_user' });
      expect(fetchUserinfo).not.toHaveBeenCalled();
      expect(await testPrisma.user.count()).toBe(0);
    });

    it('rejects a body that is not a PKCE login', async () => {
      const { response } = await login({ code_verifier: 'too-short' });

      expect(response?.status).toBe(400);
      expect(exchangeCode).not.toHaveBeenCalled();
    });

    describe('account resolution', () => {
      it('resolves a known credential to its INTERNAL user id, even when no source carries an email', async () => {
        const { userId } = await seedAccount({ subject: 'veteran' });
        providerSays({ sub: 'veteran' });

        const { data, response } = await login();

        expect(response?.status).toBe(200);
        expect(data?.user_id).toBe(userId);
      });

      it('mints a User + OidcAccount on first contact', async () => {
        providerSays({ ...VERIFIED, sub: 'newcomer' });

        const { data } = await login();
        const accounts = await testPrisma.oidcAccount.findMany({ where: { subject: 'newcomer' } });

        expect(accounts).toHaveLength(1);
        expect(accounts[0].userId).toBe(data?.user_id);
        expect(await testPrisma.user.findUniqueOrThrow({ where: { id: data!.user_id } })).toMatchObject({ firstName: 'Alice', lastName: 'Martin' });
      });

      it('403s at first contact when no source yields an email', async () => {
        providerSays({ sub: 'no-email' });

        const { error, response } = await login();

        expect(response?.status).toBe(403);
        expect(error).toMatchObject({ code: 'email_claim_required' });
        expect(await testPrisma.user.count()).toBe(0);
      });

      it('accepts an unverified email at first contact only when the deployment opted in', async () => {
        providerSays({ sub: 'unverified-newcomer', email: 'unverified@example.org' });

        expect((await login()).response?.status).toBe(403);

        mutableEnv.OIDC_ACCEPT_UNVERIFIED_EMAIL = true;

        expect((await login()).response?.status).toBe(200);
      });

      it('403s, and hands no ID token back, for a retired credential', async () => {
        await seedAccount({ disabledAt: new Date() });
        providerSays(VERIFIED);

        const { error, response } = await login();

        expect(response?.status).toBe(403);
        expect(error).toMatchObject({ code: 'forbidden' });
      });

      it('adopts the winner row when a concurrent first login already minted the user', async () => {
        const winner = await testPrisma.user.create({ data: { email: 'racer@example.org' } });
        // The lookup misses (race window), the create then hits the unique.
        const original = testPrisma.oidcAccount.findUnique.bind(testPrisma.oidcAccount);
        let calls = 0;

        vi.spyOn(testPrisma.oidcAccount, 'findUnique').mockImplementation(((args: Parameters<typeof original>[0]) =>
          calls++ === 0 ? Promise.resolve(null) : original(args)) as unknown as typeof original);
        await testPrisma.oidcAccount.create({ data: { userId: winner.id, issuer: ISSUER, subject: 'racer' } });
        providerSays({ ...VERIFIED, sub: 'racer' });

        const { data, response } = await login();

        expect(response?.status).toBe(200);
        expect(data?.user_id).toBe(winner.id);
        vi.restoreAllMocks();
      });

      it('refreshes the stored email and language at login when the provider changed them', async () => {
        const { userId } = await seedAccount({ email: 'old@example.org' });
        providerSays({ email: 'new@example.org', email_verified: true, locale: 'fr' });

        await login();

        expect(await testPrisma.user.findUniqueOrThrow({ where: { id: userId } })).toMatchObject({ email: 'new@example.org', language: 'fr' });
      });

      it('refreshes the stored names at login when the provider changed them', async () => {
        const { userId } = await seedAccount();
        await testPrisma.user.update({ where: { id: userId }, data: { firstName: 'Alicia', lastName: 'Durand' } });
        providerSays(VERIFIED);

        await login();

        expect(await testPrisma.user.findUniqueOrThrow({ where: { id: userId } })).toMatchObject({ firstName: 'Alice', lastName: 'Martin' });
      });

      it("takes the interface's language when the provider sends no locale, and the provider's over it", async () => {
        providerSays({}, { userinfo: VERIFIED });
        const { data } = await login({ language: 'fr' });
        const userId = data!.user_id;

        expect(await testPrisma.user.findUniqueOrThrow({ where: { id: userId } })).toMatchObject({ language: 'fr' });

        providerSays({}, { userinfo: { ...VERIFIED, locale: 'en-GB' } });
        await login({ language: 'fr' });

        expect(await testPrisma.user.findUniqueOrThrow({ where: { id: userId } })).toMatchObject({ language: 'en' });

        providerSays({}, { userinfo: VERIFIED });
        await login();

        expect(await testPrisma.user.findUniqueOrThrow({ where: { id: userId } })).toMatchObject({ language: 'en' });
      });

      it('records the login on the credential (lastSeenAt)', async () => {
        const longAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const { accountId } = await seedAccount({ lastSeenAt: longAgo });
        providerSays(VERIFIED);

        await login();

        const account = await testPrisma.oidcAccount.findUniqueOrThrow({ where: { id: accountId } });

        expect(account.lastSeenAt.getTime()).toBeGreaterThan(longAgo.getTime());
      });

      it('links an unknown credential to the single recently active user holding its VERIFIED email when the fallback flag is on', async () => {
        mutableEnv.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = true;
        const existing = await seedCandidate('same@example.org');
        providerSays({ sub: 'new-sub-after-migration', email: 'same@example.org', email_verified: true });

        const { data } = await login();

        expect(data?.user_id).toBe(existing);
        expect(await testPrisma.user.findUniqueOrThrow({ where: { id: existing } })).toMatchObject({ firstName: 'Alice', lastName: 'Martin' });
      });

      it('mints a fresh user instead of linking when the email is ambiguous, or the sole match dormant for over a year', async () => {
        mutableEnv.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = true;
        await seedCandidate('shared@example.org');
        await seedCandidate('shared@example.org');
        const dormant = await seedCandidate('dormant@example.org', new Date(Date.now() - 400 * 24 * 60 * 60 * 1000));

        providerSays({ sub: 'ambiguous', email: 'shared@example.org', email_verified: true });
        const ambiguous = await login();
        providerSays({ sub: 'late-comer', email: 'dormant@example.org', email_verified: true });
        const late = await login();

        expect(await testPrisma.user.count({ where: { id: ambiguous.data!.user_id, email: 'shared@example.org' } })).toBe(1);
        expect(late.data?.user_id).not.toBe(dormant);
      });

      it('never links by email when the fallback flag is off, or when the email is unverified', async () => {
        const existing = await seedCandidate('a@example.org');
        providerSays({ sub: 'no-fallback', email: 'a@example.org', email_verified: true });

        expect((await login()).data?.user_id).not.toBe(existing);

        mutableEnv.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION = true;
        mutableEnv.OIDC_ACCEPT_UNVERIFIED_EMAIL = true;
        const other = await seedCandidate('b@example.org');
        providerSays({ sub: 'unverified-sub', email: 'b@example.org' });

        expect((await login()).data?.user_id).not.toBe(other);
      });
    });
  });
});
