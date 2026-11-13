/**
 * The deployment's maintenance escrow keys, as the vault sees them, and the
 * choice of the one a resource's copy is made for.
 *
 * The server puts the configured public keys in the runtime-config data block, at
 * the same trust level as the allowed origins, and they are parsed once: a
 * malformed key is a deployment error the server already refuses at boot, so here
 * it only guards against a tampered document and fails every wrap rather than
 * silently escrowing nothing.
 *
 * Which key: the one covering the resource OWNER's email, which only the server
 * knows (from the identity provider). It answers with a fingerprint, and the vault
 * wraps only for a key of its own runtime config with that fingerprint, so the
 * answer can pick among the configured keys, never introduce one.
 *
 * Never a recipient: the copy is made by the wrap operations themselves, after
 * the recipient trust gate has run, and returned in a field of its own. A product
 * cannot inject a key, remove the copy, or make the vault wrap for a key the
 * deployment did not configure; naming the owner is all it does.
 */
import { type MaintenancePublicKey, importMaintenancePublicKey, maintenanceKeyIdToFingerprint } from '@encryption/src/crypto';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { runtimeConfig } from '@encryption/src/vault/runtime-config';

const API_BASE = '';

let configured: Promise<Map<string, MaintenancePublicKey>> | undefined;

/** The configured keys by fingerprint; empty when the deployment escrows nothing. */
export function getMaintenanceKeys(): Promise<Map<string, MaintenancePublicKey>> {
  configured ??= Promise.all((runtimeConfig.maintenanceEscrowPublicKeys ?? []).map(importMaintenancePublicKey)).then(
    (keys) => new Map(keys.map((key) => [maintenanceKeyIdToFingerprint(key.keyId), key]))
  );

  return configured;
}

/** Whose resource it is: the vault's own user (an internal id), or a user a product names by sub. */
export type MaintenanceOwner = { userId: string } | { sub: string };

// An owner's key changes only with their email or the deployment's config, so an
// answer is kept a while: a Drive upload of a hundred files asks once, not per
// file. A failed request is not kept, the next wrap asks again.
const ASSIGNMENT_TTL_MS = 5 * 60_000;

const assignments = new Map<string, { expiresAt: number; fingerprint: Promise<string | null> }>();

function fetchAssignment(owner: MaintenanceOwner): Promise<string | null> {
  const cacheKey = 'userId' in owner ? `user_id:${owner.userId}` : `sub:${owner.sub}`;
  const cached = assignments.get(cacheKey);

  if (cached && cached.expiresAt > Date.now()) return cached.fingerprint;

  const fingerprint = (async () => {
    const params = new URLSearchParams('userId' in owner ? { user_id: owner.userId } : { sub: owner.sub });
    const response = await fetch(`${API_BASE}/api/maintenance-escrow/assignment?${params.toString()}`);

    if (!response.ok) {
      throw new Error(`Failed to fetch the maintenance escrow assignment: ${response.status}`);
    }

    return ((await response.json()) as { key_fingerprint: string | null }).key_fingerprint;
  })();
  const entry = { expiresAt: Date.now() + ASSIGNMENT_TTL_MS, fingerprint };

  assignments.set(cacheKey, entry);
  fingerprint.catch(() => {
    if (assignments.get(cacheKey) === entry) assignments.delete(cacheKey);
  });

  return fingerprint;
}

/** The key the owner's resources are escrowed for, or null when no configured key covers them. */
export async function resolveMaintenanceKey(owner: MaintenanceOwner): Promise<MaintenancePublicKey | null> {
  const keys = await getMaintenanceKeys();

  if (keys.size === 0) return null;

  // null: no configured key covers the owner, or the service has no account for
  // them (no email to go by). No copy rather than a failed share: the product's
  // backfill makes it once the owner is covered.
  const fingerprint = await fetchAssignment(owner);

  if (fingerprint === null) return null;

  const key = keys.get(fingerprint);

  if (!key) {
    throw new VaultError(
      VaultErrorCode.INVALID_MAINTENANCE_KEY,
      `The server assigned the maintenance key ${fingerprint}, which is not one of the configured keys`
    );
  }

  return key;
}
