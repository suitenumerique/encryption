import type { FastifyInstance, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { createRemoteJWKSet, jwtVerify } from 'jose';

import { prisma } from '@encryption/src/prisma/client';
import { env } from '@encryption/src/server/env';
import { API_ERROR_EMAIL_CLAIM_REQUIRED, API_ERROR_FORBIDDEN, API_ERROR_UNAUTHORIZED } from '@encryption/src/shared/error-codes';

declare module 'fastify' {
  interface FastifyRequest {
    /**
     * The INTERNAL user id (users.id), never the OIDC sub. Set by verifyJWT
     * after resolving the token's (iss, sub) through oidc_accounts.
     */
    userId?: string;
  }
  interface FastifyInstance {
    verifyJWT: (request: FastifyRequest) => Promise<void>;
  }
}

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJWKS(): ReturnType<typeof createRemoteJWKSet> {
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(env.OIDC_JWKS_URL));
  }

  return jwks;
}

// Bump oidc_accounts.lastSeenAt at most once per day: its only consumer is a
// human deciding, months after a provider migration, which credentials are
// dead, so daily granularity is plenty and avoids a write per request.
const LAST_SEEN_THROTTLE_MS = 24 * 60 * 60 * 1000;

// Email fallback only links to a user seen within the last year. A provider
// migration links people who are still around; an address whose every
// credential has been dormant longer is more likely to have been recycled to a
// different human (released address, homonym hired later), and linking would
// hand them the previous holder's identity. Dormant matches fall through to a
// fresh account; an operator can still merge deliberately.
const EMAIL_FALLBACK_MAX_DORMANCY_MS = 365 * 24 * 60 * 60 * 1000;

function isUniqueViolation(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: unknown }).code === 'P2002';
}

interface UsableEmails {
  /** Address good enough to STORE (notifications): provider-verified, or any present address when OIDC_ACCEPT_UNVERIFIED_EMAIL is set. */
  email: string | null;
  /** Address good enough to IDENTIFY (email fallback): provider-verified only, always — linking decides which signed identity a login lands on. */
  identificationEmail: string | null;
}

function extractEmails(claims: Record<string, unknown>): UsableEmails {
  const rawEmail = typeof claims.email === 'string' && claims.email.length > 0 ? claims.email : null;
  const emailVerified = claims.email_verified === true;

  return {
    email: rawEmail !== null && (emailVerified || env.OIDC_ACCEPT_UNVERIFIED_EMAIL) ? rawEmail : null,
    identificationEmail: emailVerified ? rawEmail : null,
  };
}

// Discovered lazily from the issuer's metadata, cached only on success so a
// transient discovery failure is retried the next time an email is needed.
let userinfoEndpoint: string | null | undefined;

async function discoverUserinfoEndpoint(): Promise<string | null> {
  if (userinfoEndpoint !== undefined) return userinfoEndpoint;

  const response = await fetch(`${env.OIDC_ISSUER.replace(/\/$/, '')}/.well-known/openid-configuration`);

  if (!response.ok) return null;

  const metadata = (await response.json()) as { userinfo_endpoint?: unknown };
  userinfoEndpoint = typeof metadata.userinfo_endpoint === 'string' ? metadata.userinfo_endpoint : null;

  return userinfoEndpoint;
}

// Some providers (ProConnect among them) keep email out of ACCESS tokens and
// only serve it from the userinfo endpoint — LaSuite products get it there
// too, through their login flow (lasuite.oidc_login). This server has no login
// flow, so when a first contact needs an email the token does not carry, ask
// userinfo with the presented access token. ProConnect signs its userinfo
// response (application/jwt), so both shapes are handled; the signed one is
// verified against the same JWKS and issuer as the access token. Any failure
// resolves to "no email" and surfaces as email_claim_required, never a 500.
async function fetchUserinfoEmails(accessToken: string): Promise<UsableEmails> {
  const none: UsableEmails = { email: null, identificationEmail: null };

  try {
    const endpoint = await discoverUserinfoEndpoint();
    if (!endpoint) return none;

    const response = await fetch(endpoint, { headers: { authorization: `Bearer ${accessToken}` } });
    if (!response.ok) return none;

    if ((response.headers.get('content-type') ?? '').includes('application/jwt')) {
      const { payload } = await jwtVerify(await response.text(), getJWKS(), { issuer: env.OIDC_ISSUER });

      return extractEmails(payload);
    }

    return extractEmails((await response.json()) as Record<string, unknown>);
  } catch {
    return none;
  }
}

function retiredCredentialError(): Error {
  const error = new Error('Credential belongs to a retired identity provider');
  (error as NodeJS.ErrnoException).code = API_ERROR_FORBIDDEN;

  return Object.assign(error, { statusCode: 403 });
}

// Adopt the row a concurrent request just minted (our create lost the
// (issuer, subject) unique race); rethrows when no winner exists at all. A
// disabled winner gets the same 403 as the non-race path, not a 500.
async function adoptRaceWinner(issuer: string, subject: string, raceError: unknown): Promise<{ userId: string; linkedByEmail: boolean }> {
  if (!isUniqueViolation(raceError)) throw raceError;

  const winner = await prisma.oidcAccount.findUnique({ where: { issuer_subject: { issuer, subject } } });

  if (winner) {
    if (winner.disabledAt) throw retiredCredentialError();

    return { userId: winner.userId, linkedByEmail: false };
  }

  throw raceError;
}

/**
 * Resolve a verified (issuer, sub) pair to the internal user id, minting the
 * User + OidcAccount on first contact. A KNOWN credential authenticates with
 * no email at all; an email is required only at first contact (token claims
 * first, then the userinfo fallback via `fetchFallbackEmails`), because that
 * is the moment it seeds the notification channel and the migration
 * continuity anchor.
 */
async function resolveOidcAccount(
  issuer: string,
  subject: string,
  claimEmails: UsableEmails,
  fetchFallbackEmails: () => Promise<UsableEmails>
): Promise<{ userId: string; linkedByEmail: boolean }> {
  const account = await prisma.oidcAccount.findUnique({
    where: { issuer_subject: { issuer, subject } },
    include: { user: true },
  });

  if (account) {
    if (account.disabledAt) {
      throw retiredCredentialError();
    }

    const now = Date.now();
    const staleSeen = now - account.lastSeenAt.getTime() > LAST_SEEN_THROTTLE_MS;
    // The stored email refreshes opportunistically, from token claims only: a
    // userinfo round-trip per request is not worth a notification-address
    // refresh (providers that omit the claim will refresh it on the next
    // first-contact-style event instead).
    const staleEmail = claimEmails.email !== null && account.user.email !== claimEmails.email;

    // Both updates are best-effort metadata; neither gates the request.
    if (staleSeen) {
      await prisma.oidcAccount.update({ where: { id: account.id }, data: { lastSeenAt: new Date(now) } });
    }
    if (staleEmail) {
      await prisma.user.update({ where: { id: account.userId }, data: { email: claimEmails.email! } });
    }

    return { userId: account.userId, linkedByEmail: false };
  }

  // First contact for this credential — the one moment an email is REQUIRED:
  // it becomes the only notification channel (security alerts, emergency
  // access) and the only automatic continuity anchor across a provider
  // migration. By default only a provider-verified address qualifies;
  // OIDC_ACCEPT_UNVERIFIED_EMAIL loosens the verification requirement (for
  // providers that never emit email_verified), never the presence one. The
  // userinfo endpoint is only consulted when the token claims yielded nothing
  // storable, so steady-state requests never pay for it.
  const emails = claimEmails.email !== null ? claimEmails : await fetchFallbackEmails();

  if (emails.email === null) {
    const error = new Error('No usable email in the token claims or the userinfo response');
    (error as NodeJS.ErrnoException).code = API_ERROR_EMAIL_CLAIM_REQUIRED;
    throw Object.assign(error, { statusCode: 403 });
  }

  // Suite-aligned email fallback (Docs/Drive/Meet semantics): an unknown
  // credential whose VERIFIED email belongs to exactly ONE existing user is
  // linked to that user, so an OIDC provider migration keeps the same human on
  // the same encrypted identity here as in the products. Zero or several
  // matches fall through to a fresh account — never guess in a table that
  // fronts signed identities.
  if (env.OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION && emails.identificationEmail) {
    const candidates = await prisma.user.findMany({
      where: { email: emails.identificationEmail },
      include: { oidcAccounts: { orderBy: { lastSeenAt: 'desc' }, take: 1 } },
      take: 2,
    });

    // Dormancy guard: refuse to link when the sole match has not logged in for
    // over a year — the address may have been recycled to someone else since.
    const lastSeenAt = candidates.length === 1 ? candidates[0].oidcAccounts[0]?.lastSeenAt : undefined;
    const recentlyActive = lastSeenAt !== undefined && Date.now() - lastSeenAt.getTime() <= EMAIL_FALLBACK_MAX_DORMANCY_MS;

    if (candidates.length === 1 && recentlyActive) {
      try {
        const linked = await prisma.oidcAccount.create({ data: { userId: candidates[0].id, issuer, subject } });

        return { userId: linked.userId, linkedByEmail: true };
      } catch (err) {
        return adoptRaceWinner(issuer, subject, err);
      }
    }
  }

  // Mint User + OidcAccount atomically. Concurrent first requests can race;
  // the (issuer, subject) unique makes the loser's create throw P2002, in
  // which case the winner's row is adopted.
  try {
    const created = await prisma.user.create({
      data: {
        email: emails.email,
        oidcAccounts: { create: { issuer, subject } },
      },
    });

    return { userId: created.id, linkedByEmail: false };
  } catch (err) {
    return adoptRaceWinner(issuer, subject, err);
  }
}

// Wrapped with fastify-plugin to break encapsulation — the decorator
// must be visible to route plugins registered on the same app instance.
export const jwtAuthPlugin = fp(async (app: FastifyInstance): Promise<void> => {
  app.decorate('verifyJWT', async (request: FastifyRequest) => {
    const authHeader = request.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
      const error = new Error('Missing or invalid Authorization header');
      (error as NodeJS.ErrnoException).code = API_ERROR_UNAUTHORIZED;
      throw Object.assign(error, { statusCode: 401 });
    }

    const token = authHeader.slice(7);

    // Only signature/expiry/issuer verification lives in the try: those failures
    // are genuinely "invalid token" (401). Binding the expected issuer here means
    // a token from another OIDC provider is rejected by jose itself.
    let payload: Awaited<ReturnType<typeof jwtVerify>>['payload'];

    try {
      ({ payload } = await jwtVerify(token, getJWKS(), { issuer: env.OIDC_ISSUER }));
    } catch {
      const error = new Error('Invalid or expired token');
      (error as NodeJS.ErrnoException).code = API_ERROR_UNAUTHORIZED;
      throw Object.assign(error, { statusCode: 401 });
    }

    // Authorization checks run OUTSIDE the try, so they surface their own status
    // instead of being swallowed and remapped to 401 by the catch above.

    // A valid token that was not issued for this service is a 403, not a 401.
    if (payload.azp !== env.OIDC_SERVER_CLIENT_ID) {
      const error = new Error('Token was not issued for this service');
      (error as NodeJS.ErrnoException).code = API_ERROR_FORBIDDEN;
      throw Object.assign(error, { statusCode: 403 });
    }

    // A token with no `sub` cannot be resolved to a user. Reject it.
    if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
      const error = new Error('Token has no subject');
      (error as NodeJS.ErrnoException).code = API_ERROR_UNAUTHORIZED;
      throw Object.assign(error, { statusCode: 401 });
    }

    // The sub stops here: everything past this boundary speaks the internal
    // id. The email requirement lives at FIRST CONTACT only, inside
    // resolveOidcAccount: a known credential authenticates even from a token
    // carrying no email claim, and a first contact whose token lacks one falls
    // back to the issuer's userinfo endpoint before failing.
    const claimEmails = extractEmails(payload as Record<string, unknown>);
    const resolution = await resolveOidcAccount(env.OIDC_ISSUER, payload.sub, claimEmails, () => fetchUserinfoEmails(token));

    if (resolution.linkedByEmail) {
      // The one mutation of the trust-critical mapping table that happens
      // without operator intent or cryptographic proof: leave a trace.
      request.log.info({ userId: resolution.userId }, 'linked new OIDC credential to existing user via verified-email fallback');
    }

    request.userId = resolution.userId;
  });
});
