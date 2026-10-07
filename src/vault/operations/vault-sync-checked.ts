/**
 * A sync that tells a passing glitch from a lasting integrity failure.
 *
 * Every pull downloads the whole vault, so a retry is a full re-read: it clears a
 * transient failure (a request cut short, a server caught mid-incident), not
 * tampering. When the retry fails too, the local identity is compared with the
 * directory's: a different identity is a legitimate change made on another
 * device, which the settings screen reconciles; the same identity means the
 * server's copy really does not verify, which is reported. The local state is
 * never touched by any of this: the device keeps working on its last verified copy.
 */
import { computeKeyFingerprint } from '@encryption/src/crypto';
import { activeIdentity } from '@encryption/src/crypto/vault-state';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { reportVaultError } from '@encryption/src/vault/monitoring';
import { handleFetchPublicKeys } from '@encryption/src/vault/operations/fetch-public-keys';
import { handleSync } from '@encryption/src/vault/operations/vault-sync-run';
import { loadVault } from '@encryption/src/vault/vault-keys';

export const INTEGRITY_RETRY_DELAY_MS = 5_000;

export type CheckedSyncStatus = 'ok' | 'conflict' | 'integrity-error' | 'identity-diverged';

type SyncPayload = Parameters<typeof handleSync>[1];

interface CheckedSyncDeps {
  delay: (ms: number) => Promise<void>;
}

const defaultDeps: CheckedSyncDeps = { delay: (ms) => new Promise((resolve) => setTimeout(resolve, ms)) };

// Reported once per page and user: every later wake would otherwise report the
// same lasting failure again.
const reported = new Set<string>();

export async function syncWithIntegrityRetry(
  userId: string,
  payload: SyncPayload = {},
  deps: CheckedSyncDeps = defaultDeps
): Promise<{ status: CheckedSyncStatus; revision: number }> {
  const first = await handleSync(userId, payload);
  if (first.status !== 'integrity-error') return first as { status: CheckedSyncStatus; revision: number };

  await deps.delay(INTEGRITY_RETRY_DELAY_MS);

  const second = await handleSync(userId, payload);
  if (second.status !== 'integrity-error') return second as { status: CheckedSyncStatus; revision: number };

  const identity = await compareIdentityWithDirectory(userId);
  if (identity === 'different') return { status: 'identity-diverged', revision: second.revision };

  // 'unknown' (the directory could not be reached) is not reported: the failure
  // may come from the same outage, and the next sync will classify it.
  if (identity === 'same' && !reported.has(userId)) {
    reported.add(userId);
    reportVaultError(new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'The synchronized vault failed its integrity check twice in a row.'));
  }

  return { status: 'integrity-error', revision: second.revision };
}

async function compareIdentityWithDirectory(userId: string): Promise<'same' | 'different' | 'unknown'> {
  try {
    const loaded = await loadVault(userId, { persistedOnly: true });
    const local = loaded ? activeIdentity(loaded.state) : undefined;
    if (!local) return 'unknown';

    const { users } = await handleFetchPublicKeys(userId, { userIds: [userId] });
    const remote = users[userId];

    // No active identity in the directory: disabled from another device, which
    // is a divergence the settings screen reconciles, not an integrity failure.
    if (!remote) return 'different';

    return (await computeKeyFingerprint(local.signaturePublicKey)) === remote.identityFingerprint ? 'same' : 'different';
  } catch {
    return 'unknown';
  }
}

/** For tests: forget which users were already reported. */
export function resetIntegrityReports(): void {
  reported.clear();
}
