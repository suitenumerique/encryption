/**
 * Sign-in for the encryption interface (architecture.md §2.1).
 *
 * The SERVER runs the OIDC code exchange (src/server/routes/auth.ts), since the
 * provider only accepts a client with a secret: it verifies the ID token and
 * hands it back. That ID TOKEN, never an access token, is what the interface
 * presents as the Bearer credential of every API call until it expires (about
 * an hour). The access token never leaves the server.
 *
 * The iframe cannot sign in where it is (providers refuse to be framed), so it
 * opens a NEW TAB, and the result travels back through the server, not the
 * browser: a provider page sending `Cross-Origin-Opener-Policy: same-origin`
 * cuts the link between the tab and the iframe for good, and the two share no
 * storage (the iframe's is partitioned under the product's site).
 *
 * 1. The iframe draws the state, nonce, PKCE verifier and a relay id, keeps the
 *    verifier, and opens /login in a new tab (`createSignIn`, `getLoginUrl`).
 * 2. The tab asks its opener for the parameters, while the link still exists
 *    (`receiveLoginParameters`), and goes to /api/auth/authorize, which keeps
 *    the state and challenge and redirects to the provider (`startLogin`).
 * 3. The provider sends the tab back to /auth/callback, which checks the state
 *    and deposits the code on the server under the relay id (`depositCallback`).
 * 4. Meanwhile the iframe asks the server to exchange "the code of my relay id"
 *    with its verifier until it is there (`exchangeSignIn`).
 */
import { z } from 'zod';

import { type Locale, SUPPORTED_LOCALES } from '@encryption/src/shared/locale';
import '@encryption/src/shared/zod-jitless';
import { ApiError, apiDefaults } from '@encryption/src/ui/api/client';
import { postApiAuthRelay, postApiAuthToken } from '@encryption/src/ui/api/generated/sdk.gen';

export const OIDC_LOGIN_READY_MESSAGE_TYPE = 'encryption-oidc-login-ready';
export const OIDC_LOGIN_PARAMETERS_MESSAGE_TYPE = 'encryption-oidc-login-parameters';

// How long the sign-in tab waits for its opener's parameters: they come back at
// once from an iframe that is listening, never from anything else.
const LOGIN_PARAMETERS_TIMEOUT_MS = 10_000;

/** The provider's ID token and what the server said about it, as the interface keeps it (see id-token-storage.ts). */
export const idTokenSetSchema = z.object({
  /** The provider's ID token (a signed JWT issued to our client): the Bearer credential for our API. */
  idToken: z.string(),
  /** Its `exp`, as a Unix timestamp in ms: past it, the user signs in again. */
  idTokenExpiresAt: z.number(),
  /** The OIDC subject it was issued for: what the product's user id is compared with. */
  sub: z.string(),
  /** The internal user id. */
  userId: z.string(),
  firstName: z.string(),
  lastName: z.string(),
  email: z.string().nullable(),
  /** Whether the provider reported a second factor for this sign-in. */
  secondFactor: z.boolean(),
});
export type IdTokenSet = z.infer<typeof idTokenSetSchema>;

/** What the iframe hands its sign-in tab: everything but the verifier. */
export const loginParametersSchema = z.object({
  state: z.string(),
  nonce: z.string(),
  codeChallenge: z.string(),
  relayId: z.string(),
  forceLogin: z.boolean().optional(),
  stepUp: z.boolean().optional(),
  language: z.enum(SUPPORTED_LOCALES).optional(),
});
export type LoginParameters = z.infer<typeof loginParametersSchema>;

// Kept in the SIGN-IN TAB's sessionStorage between the departure to the provider
// and the return to /auth/callback (the same tab, so the same storage).
const PENDING_LOGIN_KEY = 'encryption-pending-login';

const pendingLoginSchema = z.object({ state: z.string(), relayId: z.string() });

export interface LoginOptions {
  /** Ask the provider for credentials again even within an SSO session (used when the wrong account was detected). */
  forceLogin?: boolean;
  /**
   * A step-up (RFC 9470): a fresh authentication with a second factor, after
   * the server refused a sensitive action with `insufficient_user_authentication`.
   */
  stepUp?: boolean;
  /**
   * The interface's language (the product's, else the browser's): for the
   * provider's pages, and for the account's language when the provider sends no
   * `locale`.
   */
  language?: Locale;
}

/** One sign-in, as the iframe keeps it until the exchange: the verifier never leaves it before. */
export interface SignIn {
  parameters: LoginParameters;
  codeVerifier: string;
  /** The OIDC sub the product says is signed in: the server refuses to sign in anyone else. */
  expectedSub?: string;
}

function randomBase64Url(bytes: number): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function pkceChallenge(verifier: string): Promise<string> {
  return base64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
}

/** Draw a sign-in, in the iframe. */
export async function createSignIn(expectedSub?: string, options: LoginOptions = {}): Promise<SignIn> {
  const codeVerifier = randomBase64Url(32); // 43 characters, the RFC 7636 minimum

  return {
    parameters: {
      state: randomBase64Url(32),
      nonce: randomBase64Url(32),
      codeChallenge: await pkceChallenge(codeVerifier),
      relayId: randomBase64Url(32),
      ...(options.forceLogin ? { forceLogin: true } : {}),
      ...(options.stepUp ? { stepUp: true } : {}),
      ...(options.language ? { language: options.language } : {}),
    },
    codeVerifier,
    ...(expectedSub ? { expectedSub } : {}),
  };
}

/** The sign-in page the iframe opens in a new tab, on the interface's own origin. It carries nothing: its parameters come from the opener. */
export function getLoginUrl(): string {
  return `${window.location.origin}/login`;
}

/**
 * Ask the opener for the sign-in's parameters, in the sign-in tab. Only a
 * message from `window.opener` on the interface's own origin counts: a tab
 * opened by anyone else never starts a sign-in.
 */
export function receiveLoginParameters(timeoutMs = LOGIN_PARAMETERS_TIMEOUT_MS): Promise<LoginParameters | null> {
  const opener = window.opener as Window | null;

  if (!opener) return Promise.resolve(null);

  const interfaceOrigin = window.location.origin;

  return new Promise((resolve) => {
    function settle(parameters: LoginParameters | null) {
      clearTimeout(timer);
      window.removeEventListener('message', onMessage);
      resolve(parameters);
    }

    function onMessage(event: MessageEvent) {
      if (event.source !== opener || event.origin !== interfaceOrigin) return;
      if ((event.data as { type?: string } | null)?.type !== OIDC_LOGIN_PARAMETERS_MESSAGE_TYPE) return;

      const parsed = loginParametersSchema.safeParse((event.data as { parameters?: unknown }).parameters);

      if (parsed.success) settle(parsed.data);
    }

    const timer = setTimeout(() => settle(null), timeoutMs);

    // Listening BEFORE asking: the iframe answers at once.
    window.addEventListener('message', onMessage);
    opener.postMessage({ type: OIDC_LOGIN_READY_MESSAGE_TYPE }, interfaceOrigin);
  });
}

/** Where to send the sign-in tab, recording what its callback will check. */
export function prepareLogin(parameters: LoginParameters): string {
  sessionStorage.setItem(PENDING_LOGIN_KEY, JSON.stringify({ state: parameters.state, relayId: parameters.relayId }));

  const params = new URLSearchParams({ state: parameters.state, nonce: parameters.nonce, code_challenge: parameters.codeChallenge });

  if (parameters.stepUp) params.set('step_up', '1');
  else if (parameters.forceLogin) params.set('prompt', 'login');

  if (parameters.language) params.set('ui_locales', parameters.language);

  return `/api/auth/authorize?${params.toString()}`;
}

/** Send the sign-in tab to the provider. */
export function startLogin(parameters: LoginParameters): void {
  window.location.assign(prepareLogin(parameters));
}

/** A callback this tab has no pending sign-in for: started elsewhere, forged, or already completed. */
export class UnknownCallbackError extends Error {
  constructor() {
    super('This sign-in was not started from this tab, or it was already completed.');
    this.name = 'UnknownCallbackError';
  }
}

/**
 * Hand the provider's code to the server, in the sign-in tab back on
 * /auth/callback. The state proves this tab started the sign-in the provider is
 * answering: a callback address forged by someone else (login CSRF) arrives
 * with no pending sign-in here, or with another state, and deposits nothing.
 */
export async function depositCallback(): Promise<void> {
  const params = new URLSearchParams(window.location.search);
  const raw = sessionStorage.getItem(PENDING_LOGIN_KEY);

  // Single use: a reload of the callback page must not deposit again.
  sessionStorage.removeItem(PENDING_LOGIN_KEY);

  const providerError = params.get('error');

  if (providerError) throw new Error(params.get('error_description') ?? providerError);

  const parsed = raw ? pendingLoginSchema.safeParse(JSON.parse(raw)) : null;
  const pending = parsed?.success ? parsed.data : null;
  const code = params.get('code');

  if (!pending || !code || params.get('state') !== pending.state) throw new UnknownCallbackError();

  await postApiAuthRelay({ ...apiDefaults, body: { state: pending.state, relay_id: pending.relayId, code } });
}

export class WrongUserError extends Error {
  expectedSub: string;

  constructor(expectedSub: string) {
    super('wrong_user');
    this.name = 'WrongUserError';
    this.expectedSub = expectedSub;
  }
}

/**
 * Ask the server for the ID token of a sign-in, in the iframe: null while the
 * user is still at the provider (nothing deposited yet), to ask again. Throws
 * WrongUserError when the provider signed in someone other than the expected
 * user (the server then handed nothing back).
 */
export async function exchangeSignIn(signIn: SignIn): Promise<IdTokenSet | null> {
  const { parameters } = signIn;

  try {
    const { data, response } = await postApiAuthToken({
      ...apiDefaults,
      body: {
        relay_id: parameters.relayId,
        code_verifier: signIn.codeVerifier,
        nonce: parameters.nonce,
        ...(signIn.expectedSub ? { expected_sub: signIn.expectedSub } : {}),
        ...(parameters.language ? { language: parameters.language } : {}),
      },
    });

    if (response.status === 202 || !('id_token' in data)) return null;

    return {
      idToken: data.id_token,
      idTokenExpiresAt: new Date(data.expires_at).getTime(),
      sub: data.sub,
      userId: data.user_id,
      firstName: data.first_name,
      lastName: data.last_name,
      email: data.email,
      secondFactor: data.second_factor,
    };
  } catch (err) {
    if (err instanceof ApiError && err.code === 'wrong_user' && signIn.expectedSub) throw new WrongUserError(signIn.expectedSub);

    throw err;
  }
}

// A call started this close to the expiry could reach the server after it.
const ID_TOKEN_EXPIRY_MARGIN_MS = 60_000;

/** Whether an ID token can no longer be used, so the user has to sign in again. */
export function isIdTokenExpired(idTokenSet: IdTokenSet): boolean {
  return idTokenSet.idTokenExpiresAt - Date.now() < ID_TOKEN_EXPIRY_MARGIN_MS;
}
