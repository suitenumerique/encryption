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
 * A resource is escrowed for the key of its OWNER's email, matched as every
 * email domain group is (src/server/email-domain-groups.ts): the longest listed
 * domain on a label boundary, else the `*` entry, else no key at all.
 */
import { z } from 'zod';

import { computeMaintenanceKeyFingerprint, parseMaintenancePublicKey } from '@encryption/src/crypto/maintenance-escrow';
import { domainGroupForEmail, emailDomainSchema, refineDomainGroups } from '@encryption/src/server/email-domain-groups';

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

export const maintenanceEscrowKeysSchema = z
  .array(z.object({ domains: z.array(emailDomainSchema).min(1), publicKey }))
  .superRefine((entries, ctx) => {
    refineDomainGroups(entries, ctx);

    const keyOwner = new Map<string, number>();

    entries.forEach((entry, index) => {
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
  return domainGroupForEmail(entries, email)?.publicKey ?? null;
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
