/**
 * Fetch public keys from the encryption server API and verify each registry
 * record before handing anything back.
 *
 * This operation runs inside the vault iframe, which has direct access to the
 * encryption server. Products call it via postMessage instead of hitting the
 * server themselves. The vault verifies the identity binding signature on
 * every record (see src/crypto/key-registration.ts).
 *
 * The result is a SINGLE map keyed by the id the caller queried with (the sub
 * for `subs` queries, the internal id for `userIds` queries) — one entry
 * bundling the identity and its encryption key together. A verified entry carries the encryption key
 * that is safe to wrap for; an UNVERIFIED entry (forged / tampered / incoherent
 * directory record) carries `encryptionPublicKey: null` so a product can never
 * wrap a key for it. Keeping both in one object (rather than two parallel maps)
 * removes any chance of the two views disagreeing for a given user.
 */
import { computeKeyFingerprint, verifyKeyRegistration } from '@encryption/src/crypto';
import type { ContinuityLink } from '@encryption/src/vault/operations/identity-continuity';

// In production, the vault and the API server share the same origin (data.encryption.xx).
// The relative path works without a base URL. In dev, the Vite proxy forwards /api to the server.
const API_BASE = '';

interface DirectoryEntry {
  user_id: string; // INTERNAL encryption-service user id
  sub?: string; // echoed only for records matched through the `subs=` form
  encryption_public_key: string;
  signature_public_key: string;
  key_binding_signature: string;
  version: number;
  created_at_millis: number;
}

export interface VaultRegisteredUser {
  /**
   * INTERNAL encryption-service user id. Products never need it (they speak
   * subs); the vault keys TOFU and every persistent artifact by it.
   */
  userId: string;
  signaturePublicKey: ArrayBuffer;
  identityFingerprint: string;
  version: number;
  createdAtMillis: number;
  verified: boolean;
  // null unless verified, so an incoherent entry can't be encrypted for.
  encryptionPublicKey: ArrayBuffer | null;
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer as ArrayBuffer;
}

export async function handleFetchPublicKeys(
  _userId: string,
  payload: { userIds?: string[]; subs?: string[] }
): Promise<{ users: Record<string, VaultRegisteredUser> }> {
  const userIds = payload.userIds ?? [];
  const subs = payload.subs ?? [];

  if (userIds.length === 0 && subs.length === 0) {
    return { users: {} };
  }

  // Mirrors the server schema: one form or the other, never both — mixing
  // would make the result keying ambiguous (a record matched by both forms
  // can only be keyed one way in the returned map).
  if (userIds.length > 0 && subs.length > 0) {
    throw new Error('userIds and subs are mutually exclusive');
  }

  // One repeated parameter per id rather than a comma-joined list: subs are
  // free-form IdP identifiers and may contain any ASCII character, comma
  // included, which a joined list would shatter. URLSearchParams also handles
  // every other reserved character (`&`, `#`, `+`, whitespace).
  const params = new URLSearchParams();

  for (const sub of subs) {
    params.append('subs', sub);
  }
  for (const userId of userIds) {
    params.append('user_ids', userId);
  }

  const response = await fetch(`${API_BASE}/api/public-keys?${params.toString()}`);

  if (!response.ok) {
    throw new Error(`Failed to fetch public keys: ${response.status}`);
  }

  const data = (await response.json()) as { keys: DirectoryEntry[] };

  const users: Record<string, VaultRegisteredUser> = {};

  for (const key of data.keys) {
    const verified = await verifyKeyRegistration({
      userId: key.user_id,
      version: key.version,
      createdAtMillis: key.created_at_millis,
      encryptionPublicKeyB64: key.encryption_public_key,
      signaturePublicKeyB64: key.signature_public_key,
      keyBindingSignatureB64: key.key_binding_signature,
    });

    const identityFingerprint = await computeKeyFingerprint(key.signature_public_key);

    // Key the map by the id the CALLER used: the echoed sub for `subs` queries
    // (products/interface only ever hold subs), the internal id otherwise
    // (vault-internal callers). The internal id always travels as a field.
    users[key.sub ?? key.user_id] = {
      userId: key.user_id,
      signaturePublicKey: base64ToArrayBuffer(key.signature_public_key),
      identityFingerprint,
      version: key.version,
      createdAtMillis: key.created_at_millis,
      verified,
      // The encryption key is exposed for wrapping ONLY when the binding
      // verified; an incoherent entry gets null so it can't be encrypted for.
      encryptionPublicKey: verified ? base64ToArrayBuffer(key.encryption_public_key) : null,
    };
  }

  return { users };
}

/**
 * Fetch a contact's identity-continuity chain from the directory (current
 * identity first, back toward older ones). Runs inside the vault, which owns all
 * directory HTTP. Returns an empty chain on any failure so a mismatch stays
 * fail-safe (unknown) rather than throwing out of the fingerprint check. The
 * caller (`resolveContinuity`) re-verifies every link's signature, so a hostile
 * or unreachable server can only cause a fresh out-of-band check, never trust.
 */
export async function fetchContinuityChain(userId: string): Promise<ContinuityLink[]> {
  const response = await fetch(`${API_BASE}/api/public-keys/${encodeURIComponent(userId)}/continuity`);

  if (!response.ok) {
    return [];
  }

  const data = (await response.json()) as {
    chain: Array<{
      signature_public_key: string;
      previous_signature_public_key: string;
      generation: number;
      algo: string;
      continuity_signature: string;
    }>;
  };

  return data.chain.map((link) => ({
    signaturePublicKey: link.signature_public_key,
    previousSignaturePublicKey: link.previous_signature_public_key,
    generation: link.generation,
    algo: link.algo,
    continuitySignature: link.continuity_signature,
  }));
}
