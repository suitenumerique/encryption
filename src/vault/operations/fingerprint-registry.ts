import { getEncryptionDB } from '@encryption/src/crypto/encryption-db';
import { STORE_KNOWN_PUBLIC_KEYS } from '@encryption/src/shared/constants';

// Fingerprints are stored with a status prefix: "trusted:" or "refused:"
// e.g. "trusted:A1B2 C3D4 E5F6 7890" or "refused:A1B2 C3D4 E5F6 7890"

type FingerprintStatus = 'trusted' | 'refused' | 'unknown';

interface StoredFingerprint {
  fingerprint: string;
  status: FingerprintStatus;
}

function parseStored(value: unknown): StoredFingerprint | null {
  if (typeof value === 'string') {
    // Legacy format: just a fingerprint string
    return { fingerprint: value, status: 'trusted' };
  }

  if (value && typeof value === 'object' && 'fingerprint' in value && 'status' in value) {
    return value as StoredFingerprint;
  }

  return null;
}

/** Build the IndexedDB key for a fingerprint entry: `{localUserId}:user:{remoteUserId}` */
function fingerprintKey(localUserId: string, remoteUserId: string): string {
  return `${localUserId}:user:${remoteUserId}`;
}

export interface FingerprintCheckResult {
  userId: string;
  knownFingerprint: string | null;
  providedFingerprint: string;
  status: FingerprintStatus;
}

/**
 * Check fingerprints provided by the product against the local registry.
 *
 * The product (e.g. Docs) sends the fingerprints it stored at share time.
 * The vault compares with what it knows locally.
 *
 * - First encounter (TOFU): store as trusted, status = "trusted"
 * - Match: status = "trusted"
 * - Previously refused: status = "refused"
 * - Mismatch with a trusted fingerprint: status = "unknown" (needs user decision)
 */
export async function handleCheckFingerprints(
  userId: string,
  payload: {
    userFingerprints: Record<string, string>;
    currentUserId?: string;
  }
): Promise<{ results: FingerprintCheckResult[] }> {
  const db = await getEncryptionDB();
  const results: FingerprintCheckResult[] = [];

  // Use a single transaction for all reads + writes
  const tx = db.transaction(STORE_KNOWN_PUBLIC_KEYS, 'readwrite');
  const store = tx.objectStore(STORE_KNOWN_PUBLIC_KEYS);

  for (const [remoteUserId, providedFingerprint] of Object.entries(payload.userFingerprints)) {
    if (payload.currentUserId && remoteUserId === payload.currentUserId) {
      await store.put({ fingerprint: providedFingerprint, status: 'trusted' }, fingerprintKey(userId, remoteUserId));
      results.push({ userId: remoteUserId, knownFingerprint: providedFingerprint, providedFingerprint, status: 'trusted' });
      continue;
    }

    const raw = await store.get(fingerprintKey(userId, remoteUserId));
    const known = parseStored(raw);

    if (!known) {
      await store.put({ fingerprint: providedFingerprint, status: 'trusted' }, fingerprintKey(userId, remoteUserId));
      results.push({ userId: remoteUserId, knownFingerprint: null, providedFingerprint, status: 'trusted' });
    } else if (known.fingerprint === providedFingerprint) {
      results.push({ userId: remoteUserId, knownFingerprint: known.fingerprint, providedFingerprint, status: known.status });
    } else {
      results.push({ userId: remoteUserId, knownFingerprint: known.fingerprint, providedFingerprint, status: 'unknown' });
    }
  }

  await tx.done;

  return { results };
}

/**
 * Accept a fingerprint: mark it as trusted in the registry.
 */
export async function handleAcceptFingerprint(userId: string, payload: { userId: string; fingerprint: string }): Promise<void> {
  const db = await getEncryptionDB();

  await db.put(STORE_KNOWN_PUBLIC_KEYS, { fingerprint: payload.fingerprint, status: 'trusted' }, fingerprintKey(userId, payload.userId));
}

/**
 * Refuse a fingerprint: mark it in the registry so it appears as refused (red) in the UI.
 */
export async function handleRefuseFingerprint(userId: string, payload: { userId: string; fingerprint: string }): Promise<void> {
  const db = await getEncryptionDB();

  await db.put(STORE_KNOWN_PUBLIC_KEYS, { fingerprint: payload.fingerprint, status: 'refused' }, fingerprintKey(userId, payload.userId));
}

/**
 * Get all known fingerprints with their status for the given local user.
 */
export async function handleGetKnownFingerprints(
  userId: string
): Promise<{ fingerprints: Record<string, { fingerprint: string; status: FingerprintStatus }> }> {
  const db = await getEncryptionDB();
  const store = db.transaction(STORE_KNOWN_PUBLIC_KEYS, 'readonly').objectStore(STORE_KNOWN_PUBLIC_KEYS);
  const result: Record<string, { fingerprint: string; status: FingerprintStatus }> = {};

  const prefix = `${userId}:user:`;
  let cursor = await store.openCursor();

  while (cursor) {
    const key = String(cursor.key);

    if (key.startsWith(prefix)) {
      const parsed = parseStored(cursor.value);

      if (parsed) {
        result[key.slice(prefix.length)] = parsed;
      }
    }

    cursor = await cursor.continue();
  }

  return { fingerprints: result };
}
