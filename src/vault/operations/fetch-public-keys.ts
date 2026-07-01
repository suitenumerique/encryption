/**
 * Fetch public keys from the encryption server API and verify each registry
 * record before handing anything back.
 *
 * This operation runs inside the vault iframe, which has direct access to the
 * encryption server. Products call it via postMessage instead of hitting the
 * server themselves. The vault verifies the identity binding signature on
 * every record (see src/crypto/key-registration.ts).
 *
 * The result is a SINGLE map keyed by userId — one entry bundling the identity
 * and its encryption key together. A verified entry carries the encryption key
 * that is safe to wrap for; an UNVERIFIED entry (forged / tampered / incoherent
 * directory record) carries `encryptionPublicKey: null` so a product can never
 * wrap a key for it. Keeping both in one object (rather than two parallel maps)
 * removes any chance of the two views disagreeing for a given user.
 */
import { computeKeyFingerprint, verifyKeyRegistration } from '@encryption/src/crypto';

// In production, the vault and the API server share the same origin (data.encryption.xx).
// The relative path works without a base URL. In dev, the Vite proxy forwards /api to the server.
const API_BASE = '';

interface DirectoryEntry {
  user_id: string;
  encryption_public_key: string;
  signature_public_key: string;
  key_binding_signature: string;
  version: number;
  created_at_millis: number;
}

export interface VaultRegisteredUser {
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
  payload: { userIds: string[] }
): Promise<{ users: Record<string, VaultRegisteredUser> }> {
  if (!payload.userIds || payload.userIds.length === 0) {
    return { users: {} };
  }

  // Encode each id: an IdP `sub` is not always a UUID and may contain `&`,
  // `#`, `+`, or whitespace that would otherwise corrupt the query string. The
  // server splits on comma after decoding, so a `,` inside an id is still
  // ambiguous — encode guards every other reserved character.
  const userIdsParam = payload.userIds.map(encodeURIComponent).join(',');
  const response = await fetch(`${API_BASE}/api/public-keys?user_ids=${userIdsParam}`);

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

    users[key.user_id] = {
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
