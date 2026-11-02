/**
 * Groups of an organization's users by the domain of their email, shared by the
 * deployment options that attach something to such a group: a maintenance key
 * (MAINTENANCE_ESCROW_KEYS) and a recovery council (RECOVERY_COUNCILS).
 *
 * Both are a JSON list of entries, each listing the `domains` it covers. An email
 * belongs to the longest listed domain its own domain equals or ends with, on a
 * label boundary (`monequipe.agriculture.gouv.fr` belongs to `agriculture.gouv.fr`,
 * `fauxagriculture.gouv.fr` does not), else to the `*` entry, else to none.
 */
import { z } from 'zod';

export const ANY_EMAIL_DOMAIN = '*';

// Lowercase ASCII labels: an internationalized domain is listed in its punycode
// form (xn--…), the form email addresses carry it in.
const DOMAIN_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/;

export const emailDomainSchema = z
  .string()
  .trim()
  .toLowerCase()
  .refine((value) => value === ANY_EMAIL_DOMAIN || DOMAIN_PATTERN.test(value), {
    message: `expected a domain such as "agriculture.gouv.fr" (punycode for an internationalized one), or "${ANY_EMAIL_DOMAIN}" for every other email`,
  });

/** A domain listed by two entries makes the group of its users ambiguous: a boot error. */
export function refineDomainGroups(entries: Array<{ domains: string[] }>, ctx: z.RefinementCtx): void {
  const owner = new Map<string, number>();

  entries.forEach((entry, index) => {
    for (const listed of entry.domains) {
      if (owner.has(listed)) {
        ctx.addIssue({ code: 'custom', path: [index, 'domains'], message: `"${listed}" is already listed by entry ${owner.get(listed)}` });
      }

      owner.set(listed, index);
    }
  });
}

export function emailDomain(email: string): string {
  return email
    .slice(email.lastIndexOf('@') + 1)
    .trim()
    .toLowerCase();
}

/** The entry whose group this email belongs to, or null when none covers it. */
export function domainGroupForEmail<T extends { domains: string[] }>(entries: T[], email: string): T | null {
  const domain = emailDomain(email);
  let best: { entry: T; length: number } | null = null;
  let fallback: T | null = null;

  for (const entry of entries) {
    for (const listed of entry.domains) {
      if (listed === ANY_EMAIL_DOMAIN) {
        fallback = entry;
      } else if ((domain === listed || domain.endsWith(`.${listed}`)) && (!best || listed.length > best.length)) {
        best = { entry, length: listed.length };
      }
    }
  }

  return best?.entry ?? fallback;
}

/**
 * The env-schema preprocess of a JSON-valued variable: unset or empty is
 * `undefined` (the option is off), anything else must parse.
 */
export function jsonEnvironmentValue(hint: string) {
  return (value: unknown, ctx: z.RefinementCtx) => {
    if (value === undefined || value === '') return undefined;

    try {
      return JSON.parse(value as string);
    } catch {
      ctx.addIssue({ code: 'custom', message: hint });

      return z.NEVER;
    }
  };
}
