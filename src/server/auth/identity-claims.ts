import { env } from '@encryption/src/server/env';

type Claims = Record<string, unknown>;

/** What the server needs to know about the user at sign-in, whichever answer it came from. */
export interface IdentityClaims {
  /** The email and its `email_verified`, always from the same answer (see pickIdentity). */
  email: string | null;
  emailVerified: boolean;
  locale: string | null;
  firstName: string | null;
  lastName: string | null;
}

function text(claims: Claims, key: string): string | null {
  const value = claims[key];

  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

/** The first non-empty value among the candidate claim names, looking through the sources in order. */
function firstOf(sources: Claims[], candidates: string[]): string | null {
  for (const claims of sources) {
    for (const key of candidates) {
      const value = text(claims, key);

      if (value) return value;
    }
  }

  return null;
}

/**
 * A last name from a full name, for providers that give no last name (only
 * `given_name` and `name`): the full name without the first occurrence of
 * the first name. Names are not reliably split this way (compound first names,
 * family-name-first orders), so this is a best effort for display. A full name
 * that is only the first name yields an empty last name: the person is then
 * shown by their first name alone.
 */
export function lastNameFromFullName(fullName: string, firstName: string): string {
  const at = fullName.toLocaleLowerCase().indexOf(firstName.toLocaleLowerCase());
  const rest = at === -1 ? fullName : fullName.slice(0, at) + fullName.slice(at + firstName.length);
  const lastName = rest.replace(/\s+/g, ' ').trim();

  return lastName;
}

/**
 * Read the identity from the provider's answers, in order of authority (the ID
 * token, then userinfo). The email and its `email_verified` come from the SAME
 * answer: pairing one answer's address with another's verification flag would
 * vouch for an address nobody verified.
 */
export function pickIdentity(sources: Claims[]): IdentityClaims {
  const withEmail = sources.find((claims) => text(claims, 'email') !== null);
  const firstName = firstOf(sources, env.OIDC_CLAIMS_FIRST_NAME);
  const fullName = firstOf(sources, env.OIDC_CLAIMS_FULL_NAME);
  const lastName = firstOf(sources, env.OIDC_CLAIMS_LAST_NAME) ?? (fullName && firstName ? lastNameFromFullName(fullName, firstName) : null);

  return {
    email: withEmail ? text(withEmail, 'email') : null,
    emailVerified: withEmail?.email_verified === true,
    locale: sources.map((claims) => text(claims, 'locale')).find((locale) => locale !== null) ?? null,
    firstName,
    lastName,
  };
}

/** Whether userinfo has to be asked: the ID token lacks the email or a name. */
export function isIncomplete(identity: IdentityClaims): boolean {
  return identity.email === null || identity.firstName === null || identity.lastName === null;
}

/** The userinfo part of the `claims` request parameter: the email and every configured name claim. */
export function requestedUserinfoClaims(): Record<string, { essential: true } | null> {
  const names = [...env.OIDC_CLAIMS_FIRST_NAME, ...env.OIDC_CLAIMS_LAST_NAME, ...env.OIDC_CLAIMS_FULL_NAME];

  return {
    email: { essential: true },
    email_verified: null,
    locale: null,
    ...Object.fromEntries(names.map((name) => [name, env.OIDC_CLAIMS_FIRST_NAME.includes(name) ? { essential: true } : null])),
  };
}
