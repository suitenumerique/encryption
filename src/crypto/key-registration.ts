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
// ever being mistaken for a PoP-challenge (or identity-continuity) signature,
// even across future format changes.
const REGISTRATION_DOMAIN = 'lasuite-encryption/key-registration/v1';
const POP_CHALLENGE_DOMAIN = 'lasuite-encryption/key-pop/v1';
const IDENTITY_CONTINUITY_DOMAIN = 'lasuite-encryption/identity-continuity/v1';

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
/**
 * A new identity vouched for by the previous one. Reserved for the future
 * identity-migration flow (e.g. Ed25519 → a post-quantum signature): the
 * PREVIOUS identity key signs the NEW identity's canonical bytes, so a verifier
 * who already trusts the old identity out-of-band transitively trusts the new
 * one — no fresh fingerprint check. The crypto lives here now so the format is
 * fixed and tested before any flow depends on it.
 */
export interface IdentityContinuityRecord {
  userId: string;
  /** The NEW identity's monotonic generation (previous generation + 1). */
  generation: number;
  /** The NEW identity's signature algorithm (e.g. 'ed25519', later 'ml-dsa'). */
  algo: string;
  /** The NEW identity's signature public key wire blob. */
  signaturePublicKeyWire: Uint8Array;
}

/**
 * Canonical byte string a continuity signature covers. Binds the new identity's
 * user, generation, algorithm, and public key so the previous identity's
 * endorsement can't be transplanted onto a different identity.
 */
export function encodeIdentityContinuityPayload(record: IdentityContinuityRecord): Uint8Array {
  const userIdBytes = new TextEncoder().encode(record.userId);
  const domainBytes = new TextEncoder().encode(IDENTITY_CONTINUITY_DOMAIN);
  const algoBytes = new TextEncoder().encode(record.algo);

  return concat([
    ...lengthPrefixed(domainBytes),
    ...lengthPrefixed(userIdBytes),
    writeUint32LE(record.generation),
    ...lengthPrefixed(algoBytes),
    ...lengthPrefixed(record.signaturePublicKeyWire),
  ]);
}

/**
 * Verify that a new identity is endorsed by the previous identity key. Returns
 * `false` — never throws — for a forged, tampered, or malformed record, so a
 * verifier can treat "doesn't chain" as a normal branch and fall back to a
 * fresh out-of-band check. A `true` result means: whoever holds the PREVIOUS
 * identity key deliberately vouched for this exact NEW identity.
 */
export async function verifyIdentityContinuity(
  record: IdentityContinuityRecord,
  previousSignaturePublicKeyB64: string,
  continuitySignatureB64: string
): Promise<boolean> {
  let previousRawKey: Uint8Array;
  let signature: Uint8Array;

  try {
    previousRawKey = importPublicKeyFromBase64(previousSignaturePublicKeyB64);
    signature = base64ToUint8(continuitySignatureB64);
  } catch {
    return false;
  }

  const message = encodeIdentityContinuityPayload(record);

  return verifyDetached(signature, message, previousRawKey);
}

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
