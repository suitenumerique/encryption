/**
 * @vitest-environment jsdom
 */
import { act, createElement, useEffect } from 'react';
import { type Root, createRoot } from 'react-dom/client';
import { type Mock, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ApiError } from '@encryption/src/ui/api/client';
import {
  type IdTokenSet,
  OIDC_LOGIN_PARAMETERS_MESSAGE_TYPE,
  OIDC_LOGIN_READY_MESSAGE_TYPE,
  type SignIn,
  WrongUserError,
  exchangeSignIn,
} from '@encryption/src/ui/auth/login';
import { useOidcAuth } from '@encryption/src/ui/hooks/useOidcAuth';

// The server is faked at the exchange: what the hook does with its answers.
vi.mock('@encryption/src/ui/auth/login', async (importActual) => ({
  ...(await importActual<typeof import('@encryption/src/ui/auth/login')>()),
  exchangeSignIn: vi.fn(),
}));

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const idTokenSet: IdTokenSet = {
  idToken: 'the.id.token',
  idTokenExpiresAt: Date.now() + 3_600_000,
  sub: 'user-42',
  userId: 'u',
  firstName: 'Alice',
  lastName: 'Martin',
  email: null,
  secondFactor: false,
};

let root: Root;
let latest: ReturnType<typeof useOidcAuth>;
let tabs: Window[];

function Probe() {
  const auth = useOidcAuth('user-42');

  useEffect(() => {
    latest = auth;
  });

  return null;
}

/** A window the hook opens: jsdom only takes a real window as a message source, so a frame's. */
function newTab(): Window {
  const frame = document.createElement('iframe');

  document.body.appendChild(frame);
  vi.spyOn(frame.contentWindow!, 'postMessage');
  tabs.push(frame.contentWindow!);

  return frame.contentWindow!;
}

const tabAsks = (tab: Window, origin = window.location.origin) =>
  act(async () => {
    window.dispatchEvent(new MessageEvent('message', { data: { type: OIDC_LOGIN_READY_MESSAGE_TYPE }, source: tab, origin }));
  });

/** The parameters the hook handed a tab, if any. */
const handed = (tab: Window): SignIn['parameters'] | undefined =>
  (tab.postMessage as Mock).mock.calls.find(([data]) => data?.type === OIDC_LOGIN_PARAMETERS_MESSAGE_TYPE)?.[0].parameters;

// Drawing a sign-in hashes its verifier with the real WebCrypto, which no fake timer
// advances: wait for what follows instead of counting ticks.
const handedOnce = (tab: Window) => vi.waitFor(() => handed(tab) ?? Promise.reject(new Error('nothing handed yet')));

/** The relay ids the hook asked the server about, in order. */
const exchangedRelayIds = () => vi.mocked(exchangeSignIn).mock.calls.map(([signIn]) => signIn.parameters.relayId);

const tick = (ms: number) => act(() => vi.advanceTimersByTimeAsync(ms));

beforeEach(async () => {
  vi.useFakeTimers();
  tabs = [];
  (exchangeSignIn as Mock).mockReset().mockResolvedValue(null);
  vi.spyOn(window, 'open').mockImplementation(() => newTab());

  const container = document.createElement('div');

  root = createRoot(container);
  await act(async () => root.render(createElement(Probe)));
});

afterEach(async () => {
  await act(async () => root.unmount());
  vi.useRealTimers();
  vi.restoreAllMocks();
  document.body.innerHTML = '';
});

describe('useOidcAuth', () => {
  it('opens /login, hands its tab the parameters when it asks, and waits on the server for the ID token', async () => {
    await act(async () => latest.requestAuth());

    expect(window.open).toHaveBeenCalledWith(`${window.location.origin}/login`, '_blank');
    expect(latest.isAuthenticating).toBe(true);

    await tabAsks(tabs[0]);
    const parameters = await handedOnce(tabs[0]);

    expect(parameters).toMatchObject({ state: expect.any(String), relayId: expect.any(String), codeChallenge: expect.any(String) });
    expect(tabs[0].postMessage).toHaveBeenCalledWith(expect.anything(), window.location.origin);

    await tick(5000);
    expect(exchangeSignIn).toHaveBeenCalledTimes(1);
    expect(latest.idTokenSet).toBeNull();

    (exchangeSignIn as Mock).mockResolvedValue(idTokenSet);
    await tick(5000);

    expect(latest.idTokenSet).toEqual(idTokenSet);
    expect(latest.isAuthenticating).toBe(false);
    expect(new Set(exchangedRelayIds())).toEqual(new Set([parameters?.relayId]));
  });

  it('hands the parameters to the tab it opened only, and only on the interface origin', async () => {
    await act(async () => latest.requestAuth());
    const stranger = newTab();

    await tabAsks(stranger);
    await tabAsks(tabs[0], 'https://product.example');

    expect(handed(tabs[0])).toBeUndefined();
    expect(handed(stranger)).toBeUndefined();
  });

  it('stops waiting when the user cancels', async () => {
    await act(async () => latest.requestAuth());
    await tabAsks(tabs[0]);
    await handedOnce(tabs[0]);
    await tick(5000);
    expect(exchangeSignIn).toHaveBeenCalled();

    await act(async () => latest.cancelAuth());
    const calls = (exchangeSignIn as Mock).mock.calls.length;
    await tick(5000);

    expect(latest.isAuthenticating).toBe(false);
    expect(exchangeSignIn).toHaveBeenCalledTimes(calls);
  });

  it('opens the sign-in again with a new sign-in, and drops the previous one', async () => {
    await act(async () => latest.requestAuth());
    await tabAsks(tabs[0]);
    const first = await handedOnce(tabs[0]);

    await act(async () => latest.requestAuth());
    await tabAsks(tabs[1]);
    const second = await handedOnce(tabs[1]);
    (exchangeSignIn as Mock).mockClear();
    await tick(10_000);

    expect(second?.relayId).not.toBe(first?.relayId);
    expect(exchangedRelayIds()).not.toContain(first?.relayId);
  });

  it('says so when the browser blocked the tab', async () => {
    vi.spyOn(window, 'open').mockReturnValue(null);

    await act(async () => latest.requestAuth());

    expect(latest.isAuthenticating).toBe(false);
    expect(latest.error).not.toBeNull();
    expect(exchangeSignIn).not.toHaveBeenCalled();
  });

  it('after another account was signed in, asks the provider for credentials again', async () => {
    (exchangeSignIn as Mock).mockRejectedValue(new WrongUserError('user-42'));

    await act(async () => latest.requestAuth());
    await tabAsks(tabs[0]);
    await handedOnce(tabs[0]);
    await tick(5000);
    expect(latest.wrongUser).toBe(true);

    expect(latest.isAuthenticating).toBe(false);

    (exchangeSignIn as Mock).mockResolvedValue(null);
    await act(async () => latest.requestAuth());
    await tabAsks(tabs[1]);

    expect((await handedOnce(tabs[1])).forceLogin).toBe(true);
  });
  it('asks at once when the user comes back to this window, but never twice within a second', async () => {
    await act(async () => latest.requestAuth());
    await tabAsks(tabs[0]);
    await handedOnce(tabs[0]);
    await tick(5000);
    expect(exchangeSignIn).toHaveBeenCalledTimes(1);

    // Back 100 ms after a check: the next one waits for the second to pass.
    await tick(100);
    await act(async () => window.dispatchEvent(new Event('focus')));
    await tick(800);
    expect(exchangeSignIn).toHaveBeenCalledTimes(1);
    await tick(100);
    expect(exchangeSignIn).toHaveBeenCalledTimes(2);

    // Back long after: asked right away, and the regular rhythm starts again from there.
    await tick(3000);
    await act(async () => window.dispatchEvent(new Event('focus')));
    await tick(0);
    expect(exchangeSignIn).toHaveBeenCalledTimes(3);
    await tick(4900);
    expect(exchangeSignIn).toHaveBeenCalledTimes(3);
    await tick(100);
    expect(exchangeSignIn).toHaveBeenCalledTimes(4);
  });

  it('skips a check our server did not answer (network, gateway, rate limit) and asks again at the next one', async () => {
    (exchangeSignIn as Mock)
      .mockRejectedValueOnce(new ApiError(0, 'unknown'))
      .mockRejectedValueOnce(new ApiError(503, 'unknown'))
      .mockResolvedValue(idTokenSet);

    await act(async () => latest.requestAuth());
    await tabAsks(tabs[0]);
    await handedOnce(tabs[0]);
    await tick(15_000);

    expect(exchangeSignIn).toHaveBeenCalledTimes(3);
    expect(latest.error).toBeNull();
    expect(latest.idTokenSet).toEqual(idTokenSet);
  });

  it('ends the sign-in on an answer from our server, the deposit being consumed by then', async () => {
    (exchangeSignIn as Mock).mockRejectedValue(new ApiError(401, 'oidc_login_failed'));

    await act(async () => latest.requestAuth());
    await tabAsks(tabs[0]);
    await handedOnce(tabs[0]);
    await tick(15_000);

    expect(exchangeSignIn).toHaveBeenCalledTimes(1);
    expect(latest.isAuthenticating).toBe(false);
    expect(latest.error).not.toBeNull();
    expect(latest.needsAuth).toBe(true);
  });
});
