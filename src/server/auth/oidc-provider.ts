import { type JWTPayload, createRemoteJWKSet, jwtVerify } from 'jose';

import { requestedUserinfoClaims } from '@encryption/src/server/auth/identity-claims';
import { env } from '@encryption/src/server/env';
import type { Locale } from '@encryption/src/shared/locale';

/**
 * Everything the server asks of the OIDC provider.
 *
 * The login is an authorization code flow whose code exchange happens HERE, not
 * in the browser: providers built for service providers with a backend
 * (common for public services) accept no public client, so the client secret has to
 * stay on a server. PKCE is kept on top of the secret: the browser that started
 * the login holds the verifier, so a code intercepted on its way back is useless
 * to anyone else.
 *
 * What comes out of the login is the provider's ID TOKEN, handed to the
 * interface as its Bearer credential for our API (see plugins/id-token-auth.ts).
 * The ID token is the one token whose shape OIDC fixes: always a signed JWT,
 * whose `aud` names OUR client, so an ID token issued to another product is
 * refused, and which carries how and when the user authenticated (`acr`, `amr`,
 * `auth_time`), what the step-up checks of RFC 9470 read (see step-up.ts). The
 * ACCESS token is used once, server-side, for userinfo, and dropped: OAuth 2
 * leaves its format to the provider (it is often opaque), so
 * nothing relies on reading it.
 */

/** A failure of the login itself, as opposed to a server fault: answered as 401 `oidc_login_failed`. */
export class OidcLoginError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'OidcLoginError';
  }
}

// Bounds every call to the provider, so a hung provider fails a login instead of
// holding a request (and a socket) open until the proxy gives up.
const PROVIDER_TIMEOUT_MS = 10_000;

// Tolerated clock difference with the provider when checking `exp` and `iat`.
const CLOCK_TOLERANCE_SECONDS = 30;

// The signatures accepted on what the provider signs (ID tokens, signed userinfo),
// as documented to operators: anything else is refused even if the JWKS holds a
// matching key.
const SIGNATURE_ALGORITHMS = ['RS256', 'ES256'];

interface ProviderMetadata {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string | null;
  jwks_uri: string;
}

// Cached only on success, so a provider that was down at the first login is
// discovered again at the next one instead of staying broken until a restart.
let metadata: ProviderMetadata | null = null;

export async function discoverProvider(): Promise<ProviderMetadata> {
  if (metadata) return metadata;

  const response = await fetch(`${env.OIDC_ISSUER.replace(/\/$/, '')}/.well-known/openid-configuration`, {
    signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
  });

  if (!response.ok) throw new Error(`OIDC discovery failed: ${response.status}`);

  const document = (await response.json()) as Record<string, unknown>;

  // OIDC Discovery 4.3: the document must name exactly the issuer it was fetched
  // for, or its endpoints and keys may be another provider's.
  if (document.issuer !== env.OIDC_ISSUER) {
    throw new Error(`OIDC discovery document is for issuer ${JSON.stringify(document.issuer)}, not ${env.OIDC_ISSUER}`);
  }

  const endpoint = (name: string): string | null => (typeof document[name] === 'string' ? (document[name] as string) : null);
  const authorization = endpoint('authorization_endpoint');
  const token = endpoint('token_endpoint');
  const jwksUri = endpoint('jwks_uri');

  if (!authorization || !token || !jwksUri) {
    throw new Error('OIDC discovery document lacks authorization_endpoint, token_endpoint or jwks_uri');
  }

  metadata = { authorization_endpoint: authorization, token_endpoint: token, userinfo_endpoint: endpoint('userinfo_endpoint'), jwks_uri: jwksUri };

  return metadata;
}

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

// The provider's keys, at the `jwks_uri` its discovery document names. jose
// caches them and fetches again only for an unknown `kid` (a key rotation).
async function getJWKS(): Promise<ReturnType<typeof createRemoteJWKSet>> {
  const { jwks_uri } = await discoverProvider();

  jwks ??= createRemoteJWKSet(new URL(jwks_uri));

  return jwks;
}

/** Test seam: forget the cached discovery document and JWKS. */
export function resetProviderCache(): void {
  metadata = null;
  jwks = null;
}

/**
 * The `claims` request parameter (OIDC Core 5.5), sent whatever the scopes (a
 * provider that does not support it ignores it). It does two things:
 *
 * - It asks for the user's email and names in the USERINFO answer, and nothing
 *   personal in the ID token, which travels with every API call. With the
 *   default `OIDC_SCOPES=openid`, this is how they are obtained at all:
 *   providers announcing `claims_parameter_supported` honour it. For a provider
 *   that ignores it, the deployment grants the scopes in `OIDC_SCOPES` instead,
 *   and whether the ID token then carries the claims is the provider's choice.
 * - It asks for `amr` and `auth_time` in the ID token (some providers omit `amr`
 *   unless asked), and, for a step-up, REQUIRES an `acr` among the accepted
 *   second-factor levels.
 */
export function buildClaimsParameter(stepUp: boolean): string {
  const idToken: Record<string, unknown> = { amr: { essential: true }, auth_time: { essential: true } };

  if (stepUp && env.OIDC_STEP_UP_ACR_VALUES.length > 0) {
    idToken.acr = { essential: true, values: env.OIDC_STEP_UP_ACR_VALUES };
  } else {
    idToken.acr = null;
  }

  return JSON.stringify({
    id_token: idToken,
    userinfo: requestedUserinfoClaims(),
  });
}

export interface AuthorizationRequest {
  state: string;
  nonce: string;
  codeChallenge: string;
  /** `login` forces the provider to ask for credentials again (the wrong account was signed in). */
  prompt?: 'login';
  /** The interface's language, for the provider's sign-in pages (`ui_locales`, OIDC Core 3.1.2.1). */
  uiLocale?: Locale;
  /**
   * A step-up (RFC 9470): a fresh authentication with a second factor, for an
   * action the server refused with `insufficient_user_authentication`.
   */
  stepUp?: boolean;
}

/**
 * The provider URL the login tab is sent to. The redirect URI and client id
 * come from the server's configuration, never from the request, so this cannot
 * be turned into an open redirect towards an arbitrary page.
 */
export async function buildAuthorizationUrl(request: AuthorizationRequest): Promise<string> {
  const { authorization_endpoint } = await discoverProvider();
  const url = new URL(authorization_endpoint);

  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', env.OIDC_CLIENT_ID);
  url.searchParams.set('redirect_uri', env.OIDC_REDIRECT_URI);
  url.searchParams.set('scope', env.OIDC_SCOPES);
  url.searchParams.set('state', request.state);
  url.searchParams.set('nonce', request.nonce);
  url.searchParams.set('code_challenge', request.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('claims', buildClaimsParameter(request.stepUp === true));

  // A preference, not a requirement: a provider without that language ignores it.
  if (request.uiLocale) url.searchParams.set('ui_locales', request.uiLocale);

  if (request.stepUp) {
    // Both: `max_age=0` is the standard way to demand a fresh authentication,
    // `prompt=login` the one every provider honours. `auth_time` is checked
    // afterwards anyway, so a provider that ignored both gains nothing.
    url.searchParams.set('prompt', 'login');
    url.searchParams.set('max_age', '0');
  } else if (request.prompt) {
    url.searchParams.set('prompt', request.prompt);
  }

  return url.toString();
}

/**
 * The client's authentication at the token endpoint (OIDC Core 9), as the
 * provider registered it: the secret in the form body (`client_secret_post`),
 * or as HTTP Basic credentials (`client_secret_basic`), each part
 * form-urlencoded first as RFC 6749 §2.3.1 requires.
 */
function clientAuthentication(): { headers: Record<string, string>; body: Record<string, string> } {
  if (env.OIDC_TOKEN_ENDPOINT_AUTH_METHOD === 'client_secret_basic') {
    const credentials = `${encodeURIComponent(env.OIDC_CLIENT_ID)}:${encodeURIComponent(env.OIDC_CLIENT_SECRET)}`;

    return { headers: { authorization: `Basic ${Buffer.from(credentials).toString('base64')}` }, body: {} };
  }

  return { headers: {}, body: { client_id: env.OIDC_CLIENT_ID, client_secret: env.OIDC_CLIENT_SECRET } };
}

export interface ProviderTokens {
  idToken: string;
  accessToken: string;
}

export async function exchangeCode(code: string, codeVerifier: string): Promise<ProviderTokens> {
  const { token_endpoint } = await discoverProvider();
  const client = clientAuthentication();
  const response = await fetch(token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json', ...client.headers },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: env.OIDC_REDIRECT_URI,
      code_verifier: codeVerifier,
      ...client.body,
    }),
    signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
  });

  if (!response.ok) {
    // The provider's `error` code (invalid_grant for a replayed or expired
    // code, invalid_client for a wrong secret) is safe to log: it names the
    // failure, never a credential.
    const body = (await response.json().catch(() => null)) as { error?: unknown } | null;

    throw new OidcLoginError(`token endpoint answered ${response.status} (${typeof body?.error === 'string' ? body.error : 'no error code'})`);
  }

  const body = (await response.json()) as { id_token?: unknown; access_token?: unknown };

  // OIDC Core 3.1.3.3: a code flow with the `openid` scope always returns an ID token.
  if (typeof body.id_token !== 'string' || typeof body.access_token !== 'string') {
    throw new OidcLoginError('token endpoint answered without an id_token and an access_token');
  }

  return { idToken: body.id_token, accessToken: body.access_token };
}

export type IdTokenClaims = JWTPayload & { sub: string; exp: number };

/** Why an ID token was refused. Its message is for the logs only. */
export class IdTokenError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'IdTokenError';
  }
}

/**
 * Verify an ID token issued by the provider to OUR client: signature against
 * the provider's keys, issuer, audience, expiry. Used both at login, with the
 * `nonce` that binds it to the login this browser started, and on every API
 * call, where it is the Bearer credential.
 */
export async function verifyIdToken(idToken: string, options: { nonce?: string } = {}): Promise<IdTokenClaims> {
  // Outside the try: an unreachable provider is a server fault (500), not a bad token.
  const keys = await getJWKS();
  let payload: JWTPayload;

  try {
    ({ payload } = await jwtVerify(idToken, keys, {
      issuer: env.OIDC_ISSUER,
      audience: env.OIDC_CLIENT_ID,
      algorithms: SIGNATURE_ALGORITHMS,
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      requiredClaims: ['exp', 'iat', 'sub'],
    }));
  } catch (err) {
    throw new IdTokenError(`ID token rejected: ${(err as Error).message}`);
  }

  if (options.nonce !== undefined && payload.nonce !== options.nonce) throw new IdTokenError('ID token nonce does not match the login');

  // With several audiences, `azp` names the party the token was really issued
  // to (OIDC Core 3.1.3.7): another client listed alongside us is not enough.
  if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== env.OIDC_CLIENT_ID) {
    throw new IdTokenError('ID token was issued to another party');
  }

  if (typeof payload.sub !== 'string' || payload.sub.length === 0) throw new IdTokenError('ID token has no subject');

  return payload as IdTokenClaims;
}

/**
 * The userinfo endpoint, where the email and name are requested (see
 * buildClaimsParameter). A provider may sign the answer (`application/jwt`,
 * OIDC Core 5.3.2): it is then verified against the
 * provider's keys. An ENCRYPTED answer (a JWE) would need a private key of ours
 * registered with the provider, which this deployment does not have, and fails
 * like any other error. Any failure resolves to no claims: the caller decides
 * whether what it has is enough.
 */
export async function fetchUserinfo(accessToken: string, expectedSub: string): Promise<Record<string, unknown>> {
  try {
    const { userinfo_endpoint } = await discoverProvider();
    if (!userinfo_endpoint) return {};

    const response = await fetch(userinfo_endpoint, {
      headers: { authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
    });
    if (!response.ok) return {};

    const claims = (response.headers.get('content-type') ?? '').includes('jwt')
      ? ((await jwtVerify(await response.text(), await getJWKS(), { issuer: env.OIDC_ISSUER, algorithms: SIGNATURE_ALGORITHMS })).payload as Record<
          string,
          unknown
        >)
      : ((await response.json()) as Record<string, unknown>);

    // OIDC Core 5.3.2: a userinfo answer for another subject must not be used.
    return claims.sub === expectedSub ? claims : {};
  } catch {
    return {};
  }
}
