/**
 * Sign-in for the encryption interface.
 *
 * The SERVER runs the OIDC code exchange (src/server/routes/auth.ts), since the
 * provider only accepts a client with a secret: it verifies the ID token and
 * hands it back. That ID TOKEN, never an access token, is what the interface
 * presents as the Bearer credential of every API call until it expires (about
 * an hour). The access token never leaves the server. This
 * module only does what has to happen in the browser:
 *
 * 1. The iframe opens /login in a NEW TAB (an iframe cannot be redirected to the
 *    provider: popups and framing are blocked there).
 * 2. That tab generates the state, nonce and PKCE verifier, keeps them in its
 *    own sessionStorage, and navigates to /api/auth/authorize, which redirects
 *    to the provider.
 * 3. The provider redirects back to /auth/callback, in the same tab, which checks
 *    the state and hands the code, verifier and nonce to POST /api/auth/token.
 * 4. The callback posts the resulting ID token to `window.opener`, the iframe,
 *    and closes once the iframe acknowledged it.
 */
import { z } from 'zod';

import { type Locale, SUPPORTED_LOCALES } from '@encryption/src/shared/locale';
import '@encryption/src/shared/zod-jitless';
import { ApiError, apiDefaults } from '@encryption/src/ui/api/client';
import { postApiAuthToken } from '@encryption/src/ui/api/generated/sdk.gen';

export const OIDC_AUTH_MESSAGE_TYPE = 'encryption-oidc-auth-complete';
export const OIDC_AUTH_ACK_MESSAGE_TYPE = 'encryption-oidc-auth-ack';

const AUTH_ACK_TIMEOUT_MS = 5000;

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

// Kept in the LOGIN TAB's sessionStorage between the departure to the provider
// and the return to /auth/callback (the same tab, so the same storage).
const PENDING_LOGIN_KEY = 'encryption-pending-login';

const pendingLoginSchema = z.object({
  state: z.string(),
  nonce: z.string(),
  codeVerifier: z.string(),
  expectedSub: z.string().optional(),
  language: z.enum(SUPPORTED_LOCALES).optional(),
});

export interface LoginOptions {
  /** Ask the provider for credentials again even within an SSO session (used when the wrong account was detected). */
  forceLogin?: boolean;
  /**
   * A step-up (RFC 9470): a fresh authentication with a second factor, after
   * the server refused a sensitive action with `insufficient_user_authentication`.
   */
  stepUp?: boolean;
  /**
   * The interface's language (the product's, else the browser's), handed to the
   * server for the account's language when the provider sends no `locale`. Passed
   * along from the iframe: the login tab is a top-level page, so it does not share
   * the iframe's storage and would only know the browser's language.
   */
  language?: Locale;
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

/**
 * Record a login about to start in this tab and return where to send the tab.
 * @param expectedSub - The OIDC sub the product says is signed in. Checked by the
 *   server at the end of the flow, which refuses to sign in anyone else.
 */
export async function prepareLogin(expectedSub?: string, options: LoginOptions = {}): Promise<string> {
  const pending = {
    state: randomBase64Url(32),
    nonce: randomBase64Url(32),
    codeVerifier: randomBase64Url(32), // 43 characters, the RFC 7636 minimum
    ...(expectedSub ? { expectedSub } : {}),
    ...(options.language ? { language: options.language } : {}),
  };

  sessionStorage.setItem(PENDING_LOGIN_KEY, JSON.stringify(pending));

  const params = new URLSearchParams({ state: pending.state, nonce: pending.nonce, code_challenge: await pkceChallenge(pending.codeVerifier) });

  if (options.stepUp) params.set('step_up', '1');
  else if (options.forceLogin) params.set('prompt', 'login');

  if (options.language) params.set('ui_locales', options.language);

  return `/api/auth/authorize?${params.toString()}`;
}

/** Start the login. Called from the /login page in the new tab. */
export async function startLogin(expectedSub?: string, options: LoginOptions = {}): Promise<void> {
  window.location.assign(await prepareLogin(expectedSub, options));
}

export class WrongUserError extends Error {
  expectedSub: string;
  /** The language of the login that failed, for the retry. */
  language?: Locale;

  constructor(expectedSub: string, language?: Locale) {
    super('wrong_user');
    this.name = 'WrongUserError';
    this.expectedSub = expectedSub;
    this.language = language;
  }
}

/**
 * Finish the login. Called from the /auth/callback page in the login tab.
 * Throws WrongUserError when the provider signed in someone other than the
 * expected user (the server then handed nothing back).
 */
export async function handleCallback(): Promise<IdTokenSet> {
  const params = new URLSearchParams(window.location.search);
  const raw = sessionStorage.getItem(PENDING_LOGIN_KEY);

  // Single use: a reload of the callback page must not replay the code.
  sessionStorage.removeItem(PENDING_LOGIN_KEY);

  const providerError = params.get('error');

  if (providerError) throw new Error(params.get('error_description') ?? providerError);

  const parsed = raw ? pendingLoginSchema.safeParse(JSON.parse(raw)) : null;
  const pending = parsed?.success ? parsed.data : null;
  const code = params.get('code');

  // The state proves this tab started the login the provider is answering: a
  // callback URL forged by someone else (login CSRF) arrives with no pending
  // login here, or with another state.
  if (!pending || !code || params.get('state') !== pending.state) {
    throw new Error('This sign-in was not started from this tab, or it was already completed.');
  }

  try {
    const { data } = await postApiAuthToken({
      ...apiDefaults,
      body: {
        code,
        code_verifier: pending.codeVerifier,
        nonce: pending.nonce,
        ...(pending.expectedSub ? { expected_sub: pending.expectedSub } : {}),
        ...(pending.language ? { language: pending.language } : {}),
      },
    });

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
    if (err instanceof ApiError && err.code === 'wrong_user' && pending.expectedSub) {
      throw new WrongUserError(pending.expectedSub, pending.language);
    }

    throw err;
  }
}

/**
 * Send the ID token back to the opener (the interface iframe), and resolve to
 * whether that opener acknowledged it.
 *
 * The `targetOrigin` argument is the security boundary, not a formality: the
 * browser compares it against the opener's CURRENT origin and drops the message
 * on mismatch. Any page can open this flow in a popup, so replacing it with '*'
 * would hand the ID token to whoever opened the tab.
 *
 * The acknowledgement exists because the ID token is otherwise posted blind. Only a
 * document on our own origin can send it, so a foreign opener never produces one and
 * the tab stays open instead of closing on a timer. That removes a signal an attacker
 * could otherwise read off `window.closed` — the tab closed only when the signed-in
 * `sub` matched the one they put in the URL — and it also stops a legitimate user from
 * being left silently unauthenticated when the message reached nobody.
 *
 * Uses window.opener.postMessage(): the callback tab was opened via window.open()
 * from the interface iframe. This works cross-site because it is a direct window
 * reference, not a storage API subject to Chrome's storage partitioning, which is
 * why a BroadcastChannel cannot replace it (the tab and the iframe sit in different
 * storage partitions). The opener reference is therefore load-bearing, and it is why
 * the server omits COOP on /login and /auth/callback: any COOP on those documents
 * severs it during the provider round trip.
 */
export function notifyAuthComplete(idTokenSet: IdTokenSet): Promise<boolean> {
  if (!window.opener) return Promise.resolve(false);

  const interfaceOrigin = window.location.origin;

  return new Promise((resolve) => {
    function settle(acknowledged: boolean) {
      clearTimeout(timer);
      window.removeEventListener('message', onMessage);
      resolve(acknowledged);
    }

    function onMessage(event: MessageEvent) {
      if (event.origin !== interfaceOrigin || (event.data as { type?: string } | null)?.type !== OIDC_AUTH_ACK_MESSAGE_TYPE) return;

      settle(true);
    }

    const timer = setTimeout(() => settle(false), AUTH_ACK_TIMEOUT_MS);

    // Listening BEFORE posting: the interface answers synchronously in its own message
    // handler, so a listener registered afterwards can miss the acknowledgement.
    window.addEventListener('message', onMessage);
    window.opener.postMessage({ type: OIDC_AUTH_MESSAGE_TYPE, idTokenSet }, interfaceOrigin);
  });
}

/** The login page the iframe opens in a new tab, on the interface's own origin. */
export function getLoginUrl(expectedSub?: string, options: LoginOptions = {}): string {
  const params = new URLSearchParams();

  if (expectedSub) params.set('expectedSub', expectedSub);
  if (options.forceLogin) params.set('forceLogin', '1');
  if (options.stepUp) params.set('stepUp', '1');
  if (options.language) params.set('lang', options.language);

  const qs = params.toString();

  return `${window.location.origin}/login${qs ? `?${qs}` : ''}`;
}

// A call started this close to the expiry could reach the server after it.
const ID_TOKEN_EXPIRY_MARGIN_MS = 60_000;

/** Whether an ID token can no longer be used, so the user has to sign in again. */
export function isIdTokenExpired(idTokenSet: IdTokenSet): boolean {
  return idTokenSet.idTokenExpiresAt - Date.now() < ID_TOKEN_EXPIRY_MARGIN_MS;
}
