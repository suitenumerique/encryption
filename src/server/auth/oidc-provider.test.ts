import { type CryptoKey, type JWK, SignJWT, exportJWK, generateKeyPair } from 'jose';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  IdTokenError,
  OidcLoginError,
  buildAuthorizationUrl,
  discoverProvider,
  exchangeCode,
  fetchUserinfo,
  resetProviderCache,
  verifyIdToken,
} from '@encryption/src/server/auth/oidc-provider';
import { env } from '@encryption/src/server/env';

const ISSUER = 'https://issuer.example/realms/suite';

vi.mock('@encryption/src/server/env', () => ({
  env: {
    OIDC_ISSUER: 'https://issuer.example/realms/suite',
    OIDC_CLIENT_ID: 'encryption',
    OIDC_CLIENT_SECRET: 'the-secret',
    OIDC_TOKEN_ENDPOINT_AUTH_METHOD: 'client_secret_post',
    OIDC_REDIRECT_URI: 'https://encryption.example/auth/callback',
    OIDC_SCOPES: 'openid',
    OIDC_CLAIMS_FIRST_NAME: ['given_name'],
    OIDC_CLAIMS_LAST_NAME: ['usual_name', 'family_name'],
    OIDC_CLAIMS_FULL_NAME: ['name'],
    OIDC_STEP_UP_ACR_VALUES: ['eidas1-mfa', 'eidas2'],
  },
}));

const DISCOVERY = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/auth`,
  token_endpoint: `${ISSUER}/token`,
  userinfo_endpoint: `${ISSUER}/userinfo`,
  jwks_uri: `${ISSUER}/certs`,
};

let providerKey: CryptoKey;
let publicJwk: JWK;
let foreignKey: CryptoKey;

/** A fake provider: one handler per endpoint, each overridable by a test. */
type Handler = (init: RequestInit | undefined) => Response | Promise<Response>;
let handlers: Record<string, Handler>;
const calls: { url: string; init?: RequestInit }[] = [];

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function jwtResponse(token: string, contentType: string): Response {
  return new Response(token, { status: 200, headers: { 'content-type': contentType } });
}

function form(init: RequestInit | undefined): URLSearchParams {
  return new URLSearchParams(String(init?.body ?? ''));
}

async function sign(
  claims: Record<string, unknown>,
  options: { key?: CryptoKey; issuer?: string; audience?: string | string[]; expiresAt?: string | number } = {}
) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256', kid: 'provider-key' })
    .setIssuer(options.issuer ?? ISSUER)
    .setAudience(options.audience ?? 'encryption')
    .setIssuedAt()
    .setExpirationTime(options.expiresAt ?? '1h')
    .sign(options.key ?? providerKey);
}

beforeAll(async () => {
  const pair = await generateKeyPair('ES256', { extractable: true });

  publicJwk = { ...(await exportJWK(pair.publicKey)), kid: 'provider-key', alg: 'ES256', use: 'sig' };
  providerKey = pair.privateKey;
  ({ privateKey: foreignKey } = await generateKeyPair('ES256'));
});

beforeEach(() => {
  resetProviderCache();
  calls.length = 0;
  handlers = {
    [`${ISSUER}/.well-known/openid-configuration`]: () => json(DISCOVERY),
    [`${ISSUER}/certs`]: () => json({ keys: [publicJwk] }),
  };

  vi.stubGlobal('fetch', async (input: string | URL, init?: RequestInit) => {
    const url = String(input);

    calls.push({ url, init });

    const handler = handlers[url];

    return handler ? handler(init) : new Response('not found', { status: 404 });
  });
});

describe('discoverProvider', () => {
  it('refuses a provider without a token endpoint', async () => {
    handlers[`${ISSUER}/.well-known/openid-configuration`] = () => json({ ...DISCOVERY, token_endpoint: undefined });
    await expect(discoverProvider()).rejects.toThrow(/token_endpoint/);

    handlers[`${ISSUER}/.well-known/openid-configuration`] = () => json(DISCOVERY);
    await expect(discoverProvider()).resolves.toMatchObject({ token_endpoint: `${ISSUER}/token` });
  });

  it('refuses a document naming another issuer, or no keys', async () => {
    handlers[`${ISSUER}/.well-known/openid-configuration`] = () => json({ ...DISCOVERY, issuer: 'https://evil.example' });
    await expect(discoverProvider()).rejects.toThrow(/issuer/);

    handlers[`${ISSUER}/.well-known/openid-configuration`] = () => json({ ...DISCOVERY, jwks_uri: undefined });
    await expect(discoverProvider()).rejects.toThrow(/jwks_uri/);
  });

  it('caches a successful discovery, but retries one that failed', async () => {
    handlers[`${ISSUER}/.well-known/openid-configuration`] = () => json({}, 503);
    await expect(discoverProvider()).rejects.toThrow();

    handlers[`${ISSUER}/.well-known/openid-configuration`] = () => json(DISCOVERY);
    await discoverProvider();
    await discoverProvider();

    expect(calls.filter((call) => call.url.endsWith('openid-configuration'))).toHaveLength(2);
  });
});

describe('buildAuthorizationUrl', () => {
  it('points at the discovered endpoint with the configured client and redirect, and the browser-made PKCE challenge', async () => {
    const url = new URL(await buildAuthorizationUrl({ state: 's'.repeat(43), nonce: 'n'.repeat(43), codeChallenge: 'c'.repeat(43) }));

    expect(`${url.origin}${url.pathname}`).toBe(`${ISSUER}/auth`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      response_type: 'code',
      client_id: 'encryption',
      redirect_uri: 'https://encryption.example/auth/callback',
      scope: 'openid',
      state: 's'.repeat(43),
      nonce: 'n'.repeat(43),
      code_challenge: 'c'.repeat(43),
      code_challenge_method: 'S256',
      claims: expect.any(String),
    });
  });

  it('asks for the email and name in userinfo only, and for amr and auth_time in the ID token', async () => {
    const url = new URL(await buildAuthorizationUrl({ state: 's', nonce: 'n', codeChallenge: 'c' }));
    const claims = JSON.parse(url.searchParams.get('claims')!);

    expect(claims.userinfo).toEqual({
      email: { essential: true },
      email_verified: null,
      locale: null,
      given_name: { essential: true },
      usual_name: null,
      family_name: null,
      name: null,
    });
    expect(claims.id_token).toEqual({ amr: { essential: true }, auth_time: { essential: true }, acr: null });
    expect(claims.id_token).not.toHaveProperty('email');
    expect(url.searchParams.has('max_age')).toBe(false);
  });

  it("asks for the sign-in pages in the interface's language", async () => {
    const url = new URL(await buildAuthorizationUrl({ state: 's'.repeat(43), nonce: 'n'.repeat(43), codeChallenge: 'c'.repeat(43), uiLocale: 'fr' }));

    expect(url.searchParams.get('ui_locales')).toBe('fr');
  });

  it('for a step-up, demands a fresh authentication at one of the second-factor levels', async () => {
    const url = new URL(await buildAuthorizationUrl({ state: 's', nonce: 'n', codeChallenge: 'c', stepUp: true }));
    const claims = JSON.parse(url.searchParams.get('claims')!);

    expect(claims.id_token.acr).toEqual({ essential: true, values: ['eidas1-mfa', 'eidas2'] });
    expect(url.searchParams.get('prompt')).toBe('login');
    expect(url.searchParams.get('max_age')).toBe('0');
  });

  it('forwards prompt=login to force a fresh sign-in', async () => {
    const url = new URL(await buildAuthorizationUrl({ state: 's', nonce: 'n', codeChallenge: 'c', prompt: 'login' }));

    expect(url.searchParams.get('prompt')).toBe('login');
  });
});

describe('exchangeCode', () => {
  it('posts the code, the PKCE verifier and the client secret, and returns both tokens', async () => {
    handlers[`${ISSUER}/token`] = () => json({ id_token: 'the.id.token', access_token: 'opaque-access-token', token_type: 'Bearer' });

    expect(await exchangeCode('the-code', 'the-verifier')).toEqual({ idToken: 'the.id.token', accessToken: 'opaque-access-token' });

    const sent = form(calls.find((call) => call.url === `${ISSUER}/token`)?.init);

    expect(Object.fromEntries(sent)).toEqual({
      grant_type: 'authorization_code',
      code: 'the-code',
      redirect_uri: 'https://encryption.example/auth/callback',
      code_verifier: 'the-verifier',
      client_id: 'encryption',
      client_secret: 'the-secret',
    });
  });

  it('sends the client as HTTP Basic credentials instead when the provider registered it so', async () => {
    vi.mocked(env).OIDC_TOKEN_ENDPOINT_AUTH_METHOD = 'client_secret_basic';
    vi.mocked(env).OIDC_CLIENT_SECRET = 'a:secret/with+specials';

    try {
      handlers[`${ISSUER}/token`] = () => json({ id_token: 'the.id.token', access_token: 'opaque-access-token' });

      await exchangeCode('the-code', 'the-verifier');

      const init = calls.find((call) => call.url === `${ISSUER}/token`)?.init;
      const authorization = (init?.headers as Record<string, string>).authorization;

      // RFC 6749 §2.3.1: each part form-urlencoded, then joined and base64-encoded.
      expect(Buffer.from(authorization.replace(/^Basic /, ''), 'base64').toString()).toBe('encryption:a%3Asecret%2Fwith%2Bspecials');
      expect(form(init).has('client_secret')).toBe(false);
      expect(form(init).has('client_id')).toBe(false);
    } finally {
      vi.mocked(env).OIDC_TOKEN_ENDPOINT_AUTH_METHOD = 'client_secret_post';
      vi.mocked(env).OIDC_CLIENT_SECRET = 'the-secret';
    }
  });

  it('turns a provider refusal into an OidcLoginError naming its error code', async () => {
    handlers[`${ISSUER}/token`] = () => json({ error: 'invalid_grant' }, 400);

    await expect(exchangeCode('replayed', 'v')).rejects.toThrow(new OidcLoginError('token endpoint answered 400 (invalid_grant)'));
  });

  it('refuses an answer without an ID token', async () => {
    handlers[`${ISSUER}/token`] = () => json({ access_token: 'a' });

    await expect(exchangeCode('c', 'v')).rejects.toBeInstanceOf(OidcLoginError);
  });
});

describe('verifyIdToken', () => {
  it('accepts a token signed by the provider, for our client and this login', async () => {
    const claims = await verifyIdToken(await sign({ sub: 'user-42', nonce: 'the-nonce', acr: 'eidas1' }), { nonce: 'the-nonce' });

    expect(claims).toMatchObject({ sub: 'user-42', acr: 'eidas1' });
  });

  it('accepts it without a nonce check on later API calls, where it is the Bearer credential', async () => {
    await expect(verifyIdToken(await sign({ sub: 'user-42', nonce: 'from-the-login' }))).resolves.toMatchObject({ sub: 'user-42' });
  });

  it.each([
    ['signed by another key', async () => sign({ sub: 'u', nonce: 'n' }, { key: foreignKey })],
    ['from another issuer', async () => sign({ sub: 'u', nonce: 'n' }, { issuer: 'https://evil.example' })],
    ['issued to another client', async () => sign({ sub: 'u', nonce: 'n' }, { audience: 'docs' })],
    ['for another login (nonce)', async () => sign({ sub: 'u', nonce: 'other' })],
    ['with several audiences and no azp for us', async () => sign({ sub: 'u', nonce: 'n', azp: 'docs' }, { audience: ['docs', 'encryption'] })],
    ['without a subject', async () => sign({ nonce: 'n' })],
    ['that expired', async () => sign({ sub: 'u', nonce: 'n' }, { expiresAt: Math.floor(Date.now() / 1000) - 120 })],
    ['that is not a JWT at all (an opaque access token)', async () => 'opaque-string'],
  ])('rejects a token %s', async (_label, makeToken) => {
    await expect(verifyIdToken(await makeToken(), { nonce: 'n' })).rejects.toBeInstanceOf(IdTokenError);
  });

  it('accepts several audiences when azp names us', async () => {
    const token = await sign({ sub: 'u', nonce: 'n', azp: 'encryption' }, { audience: ['docs', 'encryption'] });

    await expect(verifyIdToken(token, { nonce: 'n' })).resolves.toMatchObject({ sub: 'u' });
  });
});

describe('fetchUserinfo', () => {
  it('calls userinfo with the access token and returns its claims', async () => {
    handlers[`${ISSUER}/userinfo`] = () => json({ sub: 'user-42', email: 'u@example.org' });

    expect(await fetchUserinfo('opaque-access-token', 'user-42')).toEqual({ sub: 'user-42', email: 'u@example.org' });
    expect(new Headers(calls.find((call) => call.url === `${ISSUER}/userinfo`)?.init?.headers).get('authorization')).toBe(
      'Bearer opaque-access-token'
    );
  });

  it('verifies a signed (application/jwt) answer', async () => {
    handlers[`${ISSUER}/userinfo`] = async () => jwtResponse(await sign({ sub: 'user-42', email: 'pc@example.org' }), 'application/jwt');

    expect(await fetchUserinfo('t', 'user-42')).toMatchObject({ email: 'pc@example.org' });
  });

  it('drops an answer about another subject, a forged one, and any failure', async () => {
    handlers[`${ISSUER}/userinfo`] = () => json({ sub: 'someone-else', email: 'x@example.org' });
    expect(await fetchUserinfo('t', 'user-42')).toEqual({});

    handlers[`${ISSUER}/userinfo`] = async () =>
      jwtResponse(await sign({ sub: 'user-42', email: 'x@example.org' }, { key: foreignKey }), 'application/jwt');
    expect(await fetchUserinfo('t', 'user-42')).toEqual({});

    handlers[`${ISSUER}/userinfo`] = () => json({}, 500);
    expect(await fetchUserinfo('t', 'user-42')).toEqual({});
  });
});
