/**
 * Canonical encoding + signing of a key-registration record.
 *
 * The registry (server `public_keys` table) stores, per identity:
 *   - the encryption public key (X-Wing wire blob),
 *   - the signature public key (Ed25519 wire blob) — the IDENTITY,
 *   - a monotonic per-user `version` (1, 2, 3, …),
 *   - a creation timestamp,
 *   - a binding signature: Ed25519_sign(signatureSecret, canonicalPayload),
 *     where the payload covers ALL of the above.
 *
 * Properties this buys us:
 *   - Identity binding: the encryption key is provably chosen by the holder of
 *     the identity (signature) key. A directory that swaps in a different
 *     encryption key for a user cannot forge a matching binding signature.
 *   - Tamper-evidence / ordering: `version` and `createdAt` are inside the
 *     signed payload, so a database attacker cannot reorder, backdate, or
 *     splice rows without breaking the signature. A verifier that knows the
 *     legitimate identity key (verified out-of-band) detects any such edit.
 *
 * Both the vault (signer) and verifiers (server at registration time, other
 * users' vaults / products at share time) use this exact encoding, so the
 * bytes must be byte-for-byte deterministic. Everything is length-prefixed and
 * little-endian, and we sign over the wire blobs verbatim (the same base64 the
 * server stores and returns) to avoid any re-serialization ambiguity.
 */
import { writeUint16LE, writeUint32LE } from '@encryption/src/crypto/encryption';
import { base64ToUint8, importPublicKeyFromBase64 } from '@encryption/src/crypto/encryption-backup';
import { verifyDetached } from '@encryption/src/crypto/signature';

// Domain-separation tags. Distinct strings keep a registration signature from
// ever being mistaken for a PoP-challenge signature (or vice versa), even
// across future format changes.
const REGISTRATION_DOMAIN = 'lasuite-encryption/key-registration/v1';
const POP_CHALLENGE_DOMAIN = 'lasuite-encryption/key-pop/v1';

export interface KeyRegistrationRecord {
  /** Suite-wide user identifier (identity provider `sub`). */
  userId: string;
  /** Monotonic per-user key version, starting at 1. */
  version: number;
  /** Creation time in integer milliseconds since the epoch (signed verbatim). */
  createdAtMillis: number;
  /** Encryption public key wire blob: base64-decoded [version:1][xwing:1216]. */
  encryptionPublicKeyWire: Uint8Array;
  /** Signature (identity) public key wire blob: base64-decoded [version:1][ed25519:32]. */
  signaturePublicKeyWire: Uint8Array;
}

function writeUint64LE(value: number): Uint8Array {
  const buf = new ArrayBuffer(8);
  // Timestamps in ms stay well within Number.MAX_SAFE_INTEGER (< 2^53), so the
  // BigInt round-trip is lossless for any realistic date.
  new DataView(buf).setBigUint64(0, BigInt(value), true);

  return new Uint8Array(buf);
}

function lengthPrefixed(bytes: Uint8Array): Uint8Array[] {
  return [writeUint16LE(bytes.length), bytes];
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;

  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }

  return out;
}

/**
 * Build the canonical byte string that the binding signature covers. Both the
 * signer and every verifier must produce identical bytes for the same record.
 */
export function encodeKeyRegistrationPayload(record: KeyRegistrationRecord): Uint8Array {
  const userIdBytes = new TextEncoder().encode(record.userId);
  const domainBytes = new TextEncoder().encode(REGISTRATION_DOMAIN);

  return concat([
    ...lengthPrefixed(domainBytes),
    writeUint32LE(record.version),
    writeUint64LE(record.createdAtMillis),
    ...lengthPrefixed(userIdBytes),
    ...lengthPrefixed(record.encryptionPublicKeyWire),
    ...lengthPrefixed(record.signaturePublicKeyWire),
  ]);
}

/**
 * Message signed during the proof-of-possession `complete` step to prove the
 * caller also holds the IDENTITY (signature) secret key. Bound to the
 * server-issued `challengeId` so a captured signature can't be replayed
 * against a different challenge.
 */
export function encodePopChallengeMessage(challengeId: string): Uint8Array {
  return new TextEncoder().encode(`${POP_CHALLENGE_DOMAIN}:${challengeId}`);
}

/**
 * A registry record exactly as it travels on the wire / lives in the DB:
 * both public keys and the binding signature as base64, plus the signed
 * metadata. This is what the server returns from the directory and what the
 * server validates at registration.
 */
export interface SerializedKeyRegistration {
  userId: string;
  version: number;
  createdAtMillis: number;
  encryptionPublicKeyB64: string; // base64 [version:1][xwing]
  signaturePublicKeyB64: string; // base64 [version:1][ed25519]
  keyBindingSignatureB64: string; // base64 Ed25519 signature
}

/**
 * Verify that a registry record's binding signature is valid for its claimed
 * identity (signature) key. Returns `false` — never throws — for a forged,
 * tampered, or malformed record, so every caller (server registration, a
 * recipient's vault, a product backend) can treat "doesn't verify" as a normal
 * branch and refuse to trust the entry.
 *
 * NOTE: a `true` result means the record is internally coherent and was signed
 * by the holder of the signature key. It does NOT by itself mean that
 * signature key is the right person — that is what the out-of-band fingerprint
 * check establishes. The two together are the trust decision.
 */
export async function verifyKeyRegistration(record: SerializedKeyRegistration): Promise<boolean> {
  let encryptionPublicKeyWire: Uint8Array;
  let signaturePublicKeyWire: Uint8Array;
  let signatureRawKey: Uint8Array;
  let signature: Uint8Array;

  try {
    encryptionPublicKeyWire = base64ToUint8(record.encryptionPublicKeyB64);
    signaturePublicKeyWire = base64ToUint8(record.signaturePublicKeyB64);
    // The raw Ed25519 key (wire blob minus its version byte) is what the
    // verify primitive expects; importPublicKeyFromBase64 strips that byte and
    // rejects an unknown version.
    signatureRawKey = importPublicKeyFromBase64(record.signaturePublicKeyB64);
    signature = base64ToUint8(record.keyBindingSignatureB64);
  } catch {
    return false;
  }

  const message = encodeKeyRegistrationPayload({
    userId: record.userId,
    version: record.version,
    createdAtMillis: record.createdAtMillis,
    encryptionPublicKeyWire,
    signaturePublicKeyWire,
  });

  return verifyDetached(signature, message, signatureRawKey);
}
