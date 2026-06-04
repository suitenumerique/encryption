/**
 * Fetch public keys from the encryption server API and verify each registry
 * record before handing anything back.
 *
 * This operation runs inside the vault iframe, which has direct access to the
 * encryption server. Products call it via postMessage instead of hitting the
 * server themselves. The vault verifies the identity binding signature on
 * every record (see src/crypto/key-registration.ts), so:
 *
 *   - `publicKeys` (encryption keys, for wrapping symmetric keys) contains
 *     ONLY records whose binding verified — a product that just encrypts for
 *     recipients can keep using this map and never wrap a key for a forged or
 *     incoherent directory entry.
 *   - `identities` carries the richer per-user info, INCLUDING entries that
 *     failed verification (flagged `verified: false`), plus the identity
 *     (signature-key) fingerprint the product shows for out-of-band checks.
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

export interface VaultIdentity {
  encryptionPublicKey: ArrayBuffer;
  signaturePublicKey: ArrayBuffer;
  /** 16-hex fingerprint of the IDENTITY (signature) key — what users verify. */
  identityFingerprint: string;
  version: number;
  createdAtMillis: number;
  /** Whether the binding signature verified. `false` means do NOT trust. */
  verified: boolean;
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
): Promise<{ publicKeys: Record<string, ArrayBuffer>; identities: Record<string, VaultIdentity> }> {
  if (!payload.userIds || payload.userIds.length === 0) {
    return { publicKeys: {}, identities: {} };
  }

  const response = await fetch(`${API_BASE}/api/public-keys?user_ids=${payload.userIds.join(',')}`);

  if (!response.ok) {
    throw new Error(`Failed to fetch public keys: ${response.status}`);
  }

  const data = (await response.json()) as { keys: DirectoryEntry[] };

  const publicKeys: Record<string, ArrayBuffer> = {};
  const identities: Record<string, VaultIdentity> = {};

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

    identities[key.user_id] = {
      encryptionPublicKey: base64ToArrayBuffer(key.encryption_public_key),
      signaturePublicKey: base64ToArrayBuffer(key.signature_public_key),
      identityFingerprint,
      version: key.version,
      createdAtMillis: key.created_at_millis,
      verified,
    };

    // Only expose the encryption key for wrapping when the binding verified —
    // a product should never encrypt a key for an incoherent directory entry.
    if (verified) {
      publicKeys[key.user_id] = base64ToArrayBuffer(key.encryption_public_key);
    }
  }

  return { publicKeys, identities };
}
