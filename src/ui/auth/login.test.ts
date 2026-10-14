/**
 * @vitest-environment jsdom
 */
import { createHash } from 'node:crypto';
import { type Mock, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { apiClient } from '@encryption/src/ui/api/client';
import { clearIdTokenSet, readIdTokenSet, storeIdTokenSet, subscribeToIdTokenSet } from '@encryption/src/ui/auth/id-token-storage';
import { type IdTokenSet, WrongUserError, getLoginUrl, handleCallback, isIdTokenExpired, prepareLogin } from '@encryption/src/ui/auth/login';

const PENDING_LOGIN_KEY = 'encryption-pending-login';

function pendingLogin(): { state: string; nonce: string; codeVerifier: string; expectedSub?: string } {
  return JSON.parse(sessionStorage.getItem(PENDING_LOGIN_KEY)!);
}

function arriveOnCallback(query: string) {
  window.history.replaceState(null, '', `/auth/callback?${query}`);
}

function tokenAnswer(overrides: Record<string, unknown> = {}) {
  return {
    id_token: 'the.provider.id-token',
    expires_at: '2030-01-01T00:00:00.000Z',
    sub: 'user-42',
    user_id: '7d4f4b1e-6a8e-4c43-9f0a-1c2b3d4e5f60',
    email: 'user@example.org',
    first_name: 'Alice',
    last_name: 'Martin',
    second_factor: true,
    ...overrides,
  };
}

let fetchMock: Mock;

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
  // Same-origin in the browser; Node's Request needs the origin spelled out.
  apiClient.setConfig({ baseUrl: window.location.origin, fetch: fetchMock });
});

afterEach(() => vi.unstubAllGlobals());

describe('prepareLogin', () => {
  it('keeps a fresh state, nonce and 43-character PKCE verifier in this tab, and sends only the S256 challenge', async () => {
    const url = new URL(await prepareLogin('user-42'), 'https://encryption.example');
    const pending = pendingLogin();

    expect(url.pathname).toBe('/api/auth/authorize');
    expect(pending.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(pending.expectedSub).toBe('user-42');
    expect(url.searchParams.get('state')).toBe(pending.state);
    expect(url.searchParams.get('nonce')).toBe(pending.nonce);
    expect(url.searchParams.get('code_challenge')).toBe(createHash('sha256').update(pending.codeVerifier).digest('base64url'));
    expect(url.toString()).not.toContain(pending.codeVerifier);
    expect(url.searchParams.has('prompt')).toBe(false);
  });

  it('asks the provider for credentials again when forced', async () => {
    const url = new URL(await prepareLogin(undefined, { forceLogin: true }), 'https://encryption.example');

    expect(url.searchParams.get('prompt')).toBe('login');
  });

  it('asks the server for a step-up (RFC 9470) when confirming a sensitive action', async () => {
    const url = new URL(await prepareLogin('user-42', { stepUp: true }), 'https://encryption.example');

    expect(url.searchParams.get('step_up')).toBe('1');
    expect(url.searchParams.has('prompt')).toBe(false);
  });

  it('never reuses a state across logins', async () => {
    await prepareLogin();
    const first = pendingLogin().state;
    await prepareLogin();

    expect(pendingLogin().state).not.toBe(first);
  });
});

describe('handleCallback', () => {
  it('hands the code, the verifier and the nonce to the server and returns the ID token it verified', async () => {
    await prepareLogin('user-42');
    const pending = pendingLogin();

    arriveOnCallback(`code=the-code&state=${pending.state}`);
    fetchMock.mockResolvedValue(Response.json(tokenAnswer(), { status: 200 }));

    const idTokenSet = await handleCallback();

    expect(idTokenSet).toEqual({
      idToken: 'the.provider.id-token',
      idTokenExpiresAt: Date.parse('2030-01-01T00:00:00.000Z'),
      sub: 'user-42',
      userId: '7d4f4b1e-6a8e-4c43-9f0a-1c2b3d4e5f60',
      firstName: 'Alice',
      lastName: 'Martin',
      email: 'user@example.org',
      secondFactor: true,
    });

    const request = fetchMock.mock.calls[0][0] as Request;

    expect(new URL(request.url).pathname).toBe('/api/auth/token');
    expect(await request.json()).toEqual({ code: 'the-code', code_verifier: pending.codeVerifier, nonce: pending.nonce, expected_sub: 'user-42' });
  });

  it('refuses a callback whose state this tab did not issue (login CSRF), without calling the server', async () => {
    await prepareLogin();
    arriveOnCallback('code=the-code&state=forged');

    await expect(handleCallback()).rejects.toThrow(/not started from this tab/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refuses a callback with no login pending in this tab', async () => {
    arriveOnCallback('code=the-code&state=anything');

    await expect(handleCallback()).rejects.toThrow(/not started from this tab/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('consumes the pending login: a reloaded callback cannot replay the code', async () => {
    await prepareLogin();
    arriveOnCallback(`code=the-code&state=${pendingLogin().state}`);
    fetchMock.mockResolvedValue(Response.json(tokenAnswer(), { status: 200 }));

    await handleCallback();

    expect(sessionStorage.getItem(PENDING_LOGIN_KEY)).toBeNull();
    await expect(handleCallback()).rejects.toThrow(/not started from this tab/);
  });

  it('surfaces the error the provider sent back', async () => {
    await prepareLogin();
    arriveOnCallback(`error=access_denied&error_description=User%20cancelled&state=${pendingLogin().state}`);

    await expect(handleCallback()).rejects.toThrow('User cancelled');
  });

  it('turns the server refusing another account into WrongUserError, carrying the expected user for the retry', async () => {
    await prepareLogin('user-42');
    arriveOnCallback(`code=the-code&state=${pendingLogin().state}`);
    fetchMock.mockResolvedValue(Response.json({ code: 'wrong_user' }, { status: 409 }));

    const error = await handleCallback().catch((err: unknown) => err);

    expect(error).toBeInstanceOf(WrongUserError);
    expect((error as WrongUserError).expectedSub).toBe('user-42');
  });
});

describe('getLoginUrl', () => {
  it('opens /login on the interface origin, carrying the expected user and the force flag', () => {
    const url = new URL(getLoginUrl('user-42', { forceLogin: true }));

    expect(url.origin).toBe(window.location.origin);
    expect(url.pathname).toBe('/login');
    expect(url.searchParams.get('expectedSub')).toBe('user-42');
    expect(url.searchParams.get('forceLogin')).toBe('1');
    expect(url.searchParams.has('stepUp')).toBe(false);
  });

  it('carries the step-up flag', () => {
    expect(new URL(getLoginUrl('user-42', { stepUp: true })).searchParams.get('stepUp')).toBe('1');
  });
});

const idTokenSet = (overrides: Partial<IdTokenSet> = {}): IdTokenSet => ({
  idToken: 't',
  idTokenExpiresAt: Date.now() + 60 * 60 * 1000,
  sub: 'user-42',
  userId: 'u',
  firstName: 'Alice',
  lastName: 'Martin',
  email: null,
  secondFactor: false,
  ...overrides,
});

describe('isIdTokenExpired', () => {
  it('treats an ID token within a minute of its expiry as expired', () => {
    expect(isIdTokenExpired(idTokenSet())).toBe(false);
    expect(isIdTokenExpired(idTokenSet({ idTokenExpiresAt: Date.now() + 30_000 }))).toBe(true);
    expect(isIdTokenExpired(idTokenSet({ idTokenExpiresAt: Date.now() - 1 }))).toBe(true);
  });
});

describe('ID token storage', () => {
  it('keeps one ID token per suite user, side by side', () => {
    storeIdTokenSet('alice', idTokenSet({ sub: 'alice', idToken: 'alice-id-token' }));
    storeIdTokenSet('bob', idTokenSet({ sub: 'bob', idToken: 'bob-id-token' }));

    expect(readIdTokenSet('alice')?.idToken).toBe('alice-id-token');
    expect(readIdTokenSet('bob')?.idToken).toBe('bob-id-token');

    clearIdTokenSet('alice');

    expect(readIdTokenSet('alice')).toBeNull();
    expect(readIdTokenSet('bob')?.idToken).toBe('bob-id-token');
  });

  it('ignores a malformed entry', () => {
    localStorage.setItem('encryption-id-token:alice', '{"idToken":42}');

    expect(readIdTokenSet('alice')).toBeNull();
  });

  it('reports an ID token another page stored for this suite user, and nothing else', () => {
    const onStored = vi.fn();
    const unsubscribe = subscribeToIdTokenSet('alice', onStored);
    const storedByAnotherPage = (key: string, newValue: string | null) =>
      window.dispatchEvent(new StorageEvent('storage', { key, newValue, storageArea: localStorage }));

    storedByAnotherPage('encryption-id-token:bob', JSON.stringify(idTokenSet({ sub: 'bob' })));
    storedByAnotherPage('encryption-id-token:alice', '{"idToken":42}');
    storedByAnotherPage('encryption-id-token:alice', null);
    expect(onStored).not.toHaveBeenCalled();

    storedByAnotherPage('encryption-id-token:alice', JSON.stringify(idTokenSet({ sub: 'alice', idToken: 'alice-id-token' })));
    expect(onStored).toHaveBeenCalledWith(expect.objectContaining({ idToken: 'alice-id-token' }));

    unsubscribe();
    storedByAnotherPage('encryption-id-token:alice', JSON.stringify(idTokenSet({ sub: 'alice', idToken: 'later' })));
    expect(onStored).toHaveBeenCalledTimes(1);
  });
});
