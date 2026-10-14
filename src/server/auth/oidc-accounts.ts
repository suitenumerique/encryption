import { prisma } from '@encryption/src/prisma/client';
import { env } from '@encryption/src/server/env';
import { API_ERROR_EMAIL_CLAIM_REQUIRED, API_ERROR_FORBIDDEN } from '@encryption/src/shared/error-codes';
import type { Locale } from '@encryption/src/shared/locale';

/**
 * Map an OIDC credential (issuer + sub) the provider just vouched for to the
 * INTERNAL user id, minting the user on first contact. Runs once per login
 * (POST /api/auth/token), never per API call: the ID token handed back
 * afterwards is mapped to that id by a single lookup.
 */

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

// Map the OIDC `locale` claim (BCP47, e.g. "fr-FR") to a supported UI language.
// null when the claim is absent or unsupported, so a token that omits it never
// overwrites a previously stored preference.
function extractLanguage(claims: Record<string, unknown>): Locale | null {
  const raw = typeof claims.locale === 'string' ? claims.locale.toLowerCase() : '';

  if (raw.startsWith('fr')) return 'fr';
  if (raw.startsWith('en')) return 'en';

  return null;
}

function retiredCredentialError(): Error {
  const error = new Error('Credential belongs to a retired identity provider');
  (error as NodeJS.ErrnoException).code = API_ERROR_FORBIDDEN;

  return Object.assign(error, { statusCode: 403 });
}

export interface ResolvedAccount {
  userId: string;
  /** The credential was linked to an existing user through the verified-email fallback. */
  linkedByEmail: boolean;
}

// Adopt the row a concurrent login just minted (our create lost the
// (issuer, subject) unique race); rethrows when no winner exists at all. A
// disabled winner gets the same 403 as the non-race path, not a 500.
async function adoptRaceWinner(issuer: string, subject: string, raceError: unknown): Promise<ResolvedAccount> {
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
 * User + OidcAccount on first contact. `claims` is everything the provider said
 * about the user during this login (ID token, userinfo), already
 * merged by the caller. A KNOWN credential authenticates with no email at all;
 * an email is required only at first contact, because that is the moment it
 * seeds the notification channel and the migration continuity anchor.
 */
export async function resolveOidcAccount(issuer: string, subject: string, claims: Record<string, unknown>): Promise<ResolvedAccount> {
  const emails = extractEmails(claims);
  const language = extractLanguage(claims);
  const account = await prisma.oidcAccount.findUnique({
    where: { issuer_subject: { issuer, subject } },
    include: { user: true },
  });

  if (account) {
    if (account.disabledAt) {
      throw retiredCredentialError();
    }

    // Once per login, so no throttle: its only consumer is a human deciding,
    // months after a provider migration, which credentials are dead.
    await prisma.oidcAccount.update({ where: { id: account.id }, data: { lastSeenAt: new Date() } });

    // The stored email and language follow the provider, opportunistically: a
    // login whose claims omit them keeps what is stored.
    const staleEmail = emails.email !== null && account.user.email !== emails.email;
    const staleLanguage = language !== null && account.user.language !== language;

    if (staleEmail || staleLanguage) {
      await prisma.user.update({
        where: { id: account.userId },
        data: { ...(staleEmail ? { email: emails.email! } : {}), ...(staleLanguage ? { language } : {}) },
      });
    }

    return { userId: account.userId, linkedByEmail: false };
  }

  // First contact for this credential — the one moment an email is REQUIRED:
  // it becomes the only notification channel (security alerts, emergency
  // access) and the only automatic continuity anchor across a provider
  // migration. By default only a provider-verified address qualifies;
  // OIDC_ACCEPT_UNVERIFIED_EMAIL loosens the verification requirement (for
  // providers that never emit email_verified), never the presence one.
  if (emails.email === null) {
    const error = new Error('No usable email in the ID token or the userinfo response');
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

  // Mint User + OidcAccount atomically. Concurrent first logins can race; the
  // (issuer, subject) unique makes the loser's create throw P2002, in which
  // case the winner's row is adopted.
  try {
    const created = await prisma.user.create({
      data: {
        email: emails.email,
        ...(language ? { language } : {}),
        oidcAccounts: { create: { issuer, subject } },
      },
    });

    return { userId: created.id, linkedByEmail: false };
  } catch (err) {
    return adoptRaceWinner(issuer, subject, err);
  }
}
