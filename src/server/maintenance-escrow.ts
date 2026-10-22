/**
 * The deployment's maintenance escrow keys (architecture.md, Appendix E): one key
 * per group of email domains, so each organization sharing the deployment has its
 * own custodians and reads only its own documents.
 *
 *   MAINTENANCE_ESCROW_KEYS='[
 *     { "domains": ["agriculture.gouv.fr"], "publicKey": "AUJC…" },
 *     { "domains": ["interieur.gouv.fr", "outre-mer.gouv.fr"], "publicKey": "AUJD…" },
 *     { "domains": ["*"], "publicKey": "AUJE…" }
 *   ]'
 *
 * A resource is escrowed for the key of its OWNER's email: the longest listed
 * domain the email's domain equals or ends with, on a label boundary
 * (`monequipe.agriculture.gouv.fr` belongs to `agriculture.gouv.fr`,
 * `fauxagriculture.gouv.fr` does not), else the `*` entry, else no key at all.
 */
import { z } from 'zod';

import { computeMaintenanceKeyFingerprint, parseMaintenancePublicKey } from '@encryption/src/crypto/maintenance-escrow';

export const MAINTENANCE_ESCROW_ANY_DOMAIN = '*';

// Lowercase ASCII labels: an internationalized domain is listed in its punycode
// form (xn--…), the form email addresses carry it in.
const DOMAIN_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/;

const domain = z
  .string()
  .trim()
  .toLowerCase()
  .refine((value) => value === MAINTENANCE_ESCROW_ANY_DOMAIN || DOMAIN_PATTERN.test(value), {
    message: `expected a domain such as "agriculture.gouv.fr" (punycode for an internationalized one), or "${MAINTENANCE_ESCROW_ANY_DOMAIN}" for every other email`,
  });

const publicKey = z.string().refine(
  (value) => {
    try {
      parseMaintenancePublicKey(value);

      return true;
    } catch {
      return false;
    }
  },
  { message: 'must be a base64 X-Wing public key in the registry wire format (the one the maintenance tool generates)' }
);

export const maintenanceEscrowKeysSchema = z.array(z.object({ domains: z.array(domain).min(1), publicKey })).superRefine((entries, ctx) => {
  const domainOwner = new Map<string, number>();
  const keyOwner = new Map<string, number>();

  entries.forEach((entry, index) => {
    for (const listed of entry.domains) {
      if (domainOwner.has(listed)) {
        ctx.addIssue({ code: 'custom', path: [index, 'domains'], message: `"${listed}" is already listed by entry ${domainOwner.get(listed)}` });
      }

      domainOwner.set(listed, index);
    }

    if (keyOwner.has(entry.publicKey)) {
      ctx.addIssue({
        code: 'custom',
        path: [index, 'publicKey'],
        message: `the same key as entry ${keyOwner.get(entry.publicKey)}: list all its domains in one entry`,
      });
    }

    keyOwner.set(entry.publicKey, index);
  });
});

export type MaintenanceEscrowKeys = z.infer<typeof maintenanceEscrowKeysSchema>;

/** The configured public key that escrows resources owned by this email, or null when none does. */
export function maintenanceEscrowKeyForEmail(entries: MaintenanceEscrowKeys, email: string): string | null {
  const emailDomain = email
    .slice(email.lastIndexOf('@') + 1)
    .trim()
    .toLowerCase();
  let best: { publicKey: string; length: number } | null = null;
  let fallback: string | null = null;

  for (const entry of entries) {
    for (const listed of entry.domains) {
      if (listed === MAINTENANCE_ESCROW_ANY_DOMAIN) {
        fallback = entry.publicKey;
      } else if ((emailDomain === listed || emailDomain.endsWith(`.${listed}`)) && (!best || listed.length > best.length)) {
        best = { publicKey: entry.publicKey, length: listed.length };
      }
    }
  }

  return best?.publicKey ?? fallback;
}

const fingerprints = new Map<string, Promise<string>>();

/** Memoized: the configured keys never change while the process runs. */
export function maintenanceEscrowKeyFingerprint(publicKeyBase64: string): Promise<string> {
  let fingerprint = fingerprints.get(publicKeyBase64);

  if (!fingerprint) {
    fingerprint = computeMaintenanceKeyFingerprint(publicKeyBase64);
    fingerprints.set(publicKeyBase64, fingerprint);
  }

  return fingerprint;
}
