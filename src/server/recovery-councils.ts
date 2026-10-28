/**
 * The deployment's recovery councils (shamir.md): for each group of users, by
 * email domain, the custodians who can together give one of them their vault
 * back, and how many of them it takes.
 *
 *   RECOVERY_COUNCILS='[
 *     {
 *       "id": "dinum",
 *       "label": "Équipe sécurité DINUM",
 *       "domains": ["numerique.gouv.fr"],
 *       "custodians": [
 *         { "userId": "0b7e5f0c-…", "email": "rssi@numerique.gouv.fr" },
 *         { "userId": "6f2d4c1a-…", "email": "dpo@numerique.gouv.fr" },
 *         { "userId": "9a8b7c6d-…", "email": "dsi@numerique.gouv.fr" }
 *       ],
 *       "threshold": 2
 *     }
 *   ]'
 *
 * The variable only PROPOSES. What is in force is the roster the custodians
 * signed, in the database: a difference becomes a change for them to sign, and
 * an entry that disappears, or a variable left empty, deletes nothing.
 *
 * Users are matched by email domain exactly as maintenance keys are
 * (src/server/email-domain-groups.ts). A custodian is named by internal user id,
 * which survives an email change or a new identity provider, with their email as
 * a guard against a mistyped id: the server offers no change while the user's
 * current email differs from the one written here.
 */
import { z } from 'zod';

import { domainGroupForEmail, emailDomainSchema, refineDomainGroups } from '@encryption/src/server/email-domain-groups';

export const COUNCIL_MIN_CUSTODIANS = 2;
// Beyond a dozen, coordinating a recovery stops being realistic, and every
// enrolled user carries one capsule per custodian.
export const COUNCIL_MAX_CUSTODIANS = 12;
export const COUNCIL_DEFAULT_REQUEST_TTL_DAYS = 7;

const COUNCIL_ID_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

const custodianSchema = z.object({
  userId: z.string().uuid(),
  email: z.string().trim().toLowerCase().email(),
});

const councilSchema = z
  .object({
    id: z.string().regex(COUNCIL_ID_PATTERN, 'lowercase letters, digits and dashes, such as "dinum"'),
    label: z.string().trim().min(1).max(120),
    domains: z.array(emailDomainSchema).min(1),
    custodians: z.array(custodianSchema).min(COUNCIL_MIN_CUSTODIANS).max(COUNCIL_MAX_CUSTODIANS),
    // At least one custodian more than the threshold: one departure, absence or
    // lost device must never make every recovery impossible.
    threshold: z.number().int().min(1),
    requestTtlDays: z.number().int().min(1).max(30).default(COUNCIL_DEFAULT_REQUEST_TTL_DAYS),
    cooldownMinutes: z
      .number()
      .int()
      .min(0)
      .max(24 * 60)
      .default(0),
  })
  .superRefine((council, ctx) => {
    if (council.threshold > council.custodians.length - 1) {
      ctx.addIssue({
        code: 'custom',
        path: ['threshold'],
        message: `at most ${council.custodians.length - 1} for ${council.custodians.length} custodians: one custodian more than the threshold is required`,
      });
    }

    const ids = new Set(council.custodians.map((c) => c.userId));
    const emails = new Set(council.custodians.map((c) => c.email));

    if (ids.size !== council.custodians.length) ctx.addIssue({ code: 'custom', path: ['custodians'], message: 'a userId is listed twice' });
    if (emails.size !== council.custodians.length) ctx.addIssue({ code: 'custom', path: ['custodians'], message: 'an email is listed twice' });
  });

export const recoveryCouncilsSchema = z.array(councilSchema).superRefine((councils, ctx) => {
  refineDomainGroups(councils, ctx);

  const ids = new Set<string>();

  councils.forEach((council, index) => {
    if (ids.has(council.id)) ctx.addIssue({ code: 'custom', path: [index, 'id'], message: `"${council.id}" is already used` });
    ids.add(council.id);
  });
});

export type RecoveryCouncilConfig = z.infer<typeof councilSchema>;

/** The council proposed to a user with this email, or null. */
export function councilForEmail(councils: RecoveryCouncilConfig[], email: string): RecoveryCouncilConfig | null {
  return domainGroupForEmail(councils, email);
}

export function configuredCouncil(councils: RecoveryCouncilConfig[] | undefined, councilId: string): RecoveryCouncilConfig | null {
  return councils?.find((council) => council.id === councilId) ?? null;
}

/** Warnings worth a line in the boot log; none of them stops the server. */
export function councilWarnings(councils: RecoveryCouncilConfig[]): string[] {
  return councils.flatMap((council) => {
    const warnings: string[] = [];

    if (council.threshold === 1) {
      warnings.push(`recovery council "${council.id}": a threshold of 1 lets any single custodian give a vault back (with the user present)`);
    }

    if (council.custodians.length - council.threshold < 2) {
      warnings.push(
        `recovery council "${council.id}": ${council.custodians.length} custodians for a threshold of ${council.threshold}, a margin of 1; two absences block every recovery`
      );
    }

    return warnings;
  });
}
