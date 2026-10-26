/**
 * @vitest-environment jsdom
 */
import { createHash } from 'node:crypto';
import { type Mock, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { apiClient } from '@encryption/src/ui/api/client';
import { clearIdTokenSet, readIdTokenSet, storeIdTokenSet, subscribeToIdTokenSet } from '@encryption/src/ui/auth/id-token-storage';
import {
  type IdTokenSet,
  OIDC_LOGIN_PARAMETERS_MESSAGE_TYPE,
  OIDC_LOGIN_READY_MESSAGE_TYPE,
  UnknownCallbackError,
  WrongUserError,
  createSignIn,
  depositCallback,
  exchangeSignIn,
  getLoginUrl,
  isIdTokenExpired,
  prepareLogin,
  receiveLoginParameters,
} from '@encryption/src/ui/auth/login';

const PENDING_LOGIN_KEY = 'encryption-pending-login';

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

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  Object.defineProperty(window, 'opener', { value: null, configurable: true });
});

describe('createSignIn, in the iframe', () => {
  it('draws a fresh state, nonce, relay id and 43-character verifier, and hands out only its S256 challenge', async () => {
    const signIn = await createSignIn('user-42', { language: 'fr' });
    const { parameters } = signIn;

    expect(signIn.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(parameters.codeChallenge).toBe(createHash('sha256').update(signIn.codeVerifier).digest('base64url'));
    expect(JSON.stringify(parameters)).not.toContain(signIn.codeVerifier);
    expect(parameters.language).toBe('fr');
    expect(signIn.expectedSub).toBe('user-42');
    expect(new Set([parameters.state, parameters.nonce, parameters.relayId]).size).toBe(3);
  });

  it('never reuses a state or a relay id across sign-ins', async () => {
    const [first, second] = await Promise.all([createSignIn(), createSignIn()]);

    expect(second.parameters.state).not.toBe(first.parameters.state);
    expect(second.parameters.relayId).not.toBe(first.parameters.relayId);
  });
});

describe('getLoginUrl', () => {
  it('opens /login on the interface origin, carrying nothing: the parameters come from the opener', () => {
    expect(getLoginUrl()).toBe(`${window.location.origin}/login`);
  });
});

describe('receiveLoginParameters, in the sign-in tab', () => {
  const fromOpener = (data: unknown, source: Window | null = window, origin = window.location.origin) =>
    window.dispatchEvent(new MessageEvent('message', { data, source, origin }));

  it('starts nothing in a tab no page opened', async () => {
    await expect(receiveLoginParameters()).resolves.toBeNull();
  });

  it('asks its opener, on the interface origin only, and takes the parameters it answers', async () => {
    // The tab's own window stands in for the opener: jsdom only takes a window as a message source.
    const postMessage = vi.spyOn(window, 'postMessage');
    Object.defineProperty(window, 'opener', { value: window, configurable: true });
    const { parameters } = await createSignIn();

    const received = receiveLoginParameters();
    fromOpener({ type: OIDC_LOGIN_PARAMETERS_MESSAGE_TYPE, parameters });

    await expect(received).resolves.toEqual(parameters);
    expect(postMessage).toHaveBeenCalledWith({ type: OIDC_LOGIN_READY_MESSAGE_TYPE }, window.location.origin);
  });

  it('ignores parameters from anything but its opener on the interface origin, then gives up', async () => {
    vi.useFakeTimers();
    Object.defineProperty(window, 'opener', { value: window, configurable: true });
    const { parameters } = await createSignIn();

    const received = receiveLoginParameters(1000);
    fromOpener({ type: OIDC_LOGIN_PARAMETERS_MESSAGE_TYPE, parameters }, null);
    fromOpener({ type: OIDC_LOGIN_PARAMETERS_MESSAGE_TYPE, parameters }, window, 'https://product.example');
    vi.advanceTimersByTime(1000);

    await expect(received).resolves.toBeNull();
  });
});

describe('prepareLogin, in the sign-in tab', () => {
  it('sends the state, nonce and challenge to the server, and keeps only the state and relay id in this tab', async () => {
    const { parameters } = await createSignIn('user-42');
    const url = new URL(prepareLogin(parameters), 'https://encryption.example');

    expect(url.pathname).toBe('/api/auth/authorize');
    expect(Object.fromEntries(url.searchParams)).toEqual({
      state: parameters.state,
      nonce: parameters.nonce,
      code_challenge: parameters.codeChallenge,
    });
    expect(url.toString()).not.toContain(parameters.relayId);
    expect(JSON.parse(sessionStorage.getItem(PENDING_LOGIN_KEY)!)).toEqual({ state: parameters.state, relayId: parameters.relayId });
  });

  it('asks the provider for credentials again when forced', async () => {
    const { parameters } = await createSignIn(undefined, { forceLogin: true });

    expect(new URL(prepareLogin(parameters), 'https://encryption.example').searchParams.get('prompt')).toBe('login');
  });

  it('asks the server for a step-up (RFC 9470) when confirming a sensitive action', async () => {
    const { parameters } = await createSignIn('user-42', { stepUp: true });
    const url = new URL(prepareLogin(parameters), 'https://encryption.example');

    expect(url.searchParams.get('step_up')).toBe('1');
    expect(url.searchParams.has('prompt')).toBe(false);
  });

  it("asks for the provider's sign-in pages in the interface's language", async () => {
    const { parameters } = await createSignIn('user-42', { language: 'en' });

    expect(new URL(prepareLogin(parameters), 'https://encryption.example').searchParams.get('ui_locales')).toBe('en');
  });
});

describe('depositCallback, in the sign-in tab', () => {
  it('deposits the code on the server under the relay id, and nothing more', async () => {
    const { parameters } = await createSignIn('user-42');
    prepareLogin(parameters);
    arriveOnCallback(`code=the-code&state=${parameters.state}`);
    fetchMock.mockResolvedValue(Response.json({ status: 'deposited' }, { status: 200 }));

    await depositCallback();

    const request = fetchMock.mock.calls[0][0] as Request;

    expect(new URL(request.url).pathname).toBe('/api/auth/relay');
    expect(await request.json()).toEqual({ state: parameters.state, relay_id: parameters.relayId, code: 'the-code' });
  });

  it('refuses a callback whose state this tab did not issue (login CSRF), without calling the server', async () => {
    prepareLogin((await createSignIn()).parameters);
    arriveOnCallback('code=the-code&state=forged');

    await expect(depositCallback()).rejects.toThrow(UnknownCallbackError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refuses a callback with no sign-in pending in this tab', async () => {
    arriveOnCallback('code=the-code&state=anything');

    await expect(depositCallback()).rejects.toThrow(UnknownCallbackError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('consumes the pending sign-in: a reloaded callback cannot deposit again', async () => {
    const { parameters } = await createSignIn();
    prepareLogin(parameters);
    arriveOnCallback(`code=the-code&state=${parameters.state}`);
    fetchMock.mockResolvedValue(Response.json({ status: 'deposited' }, { status: 200 }));

    await depositCallback();

    expect(sessionStorage.getItem(PENDING_LOGIN_KEY)).toBeNull();
    await expect(depositCallback()).rejects.toThrow(UnknownCallbackError);
  });

  it('surfaces the error the provider sent back', async () => {
    const { parameters } = await createSignIn();
    prepareLogin(parameters);
    arriveOnCallback(`error=access_denied&error_description=User%20cancelled&state=${parameters.state}`);

    await expect(depositCallback()).rejects.toThrow('User cancelled');
  });
});

describe('exchangeSignIn, in the iframe', () => {
  it('waits while the server has nothing deposited yet', async () => {
    fetchMock.mockResolvedValue(Response.json({ status: 'pending' }, { status: 202 }));

    await expect(exchangeSignIn(await createSignIn('user-42'))).resolves.toBeNull();
  });

  it('exchanges with its relay id, verifier and nonce, and returns the ID token the server verified', async () => {
    const signIn = await createSignIn('user-42', { language: 'fr' });
    fetchMock.mockResolvedValue(Response.json(tokenAnswer(), { status: 200 }));

    expect(await exchangeSignIn(signIn)).toEqual({
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
    expect(await request.json()).toEqual({
      relay_id: signIn.parameters.relayId,
      code_verifier: signIn.codeVerifier,
      nonce: signIn.parameters.nonce,
      expected_sub: 'user-42',
      language: 'fr',
    });
  });

  it('turns the server refusing another account into WrongUserError, carrying the expected user', async () => {
    fetchMock.mockResolvedValue(Response.json({ code: 'wrong_user' }, { status: 409 }));

    const error = await exchangeSignIn(await createSignIn('user-42')).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(WrongUserError);
    expect((error as WrongUserError).expectedSub).toBe('user-42');
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
