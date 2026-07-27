/**
 * Emergency access (trusted contacts) escrow primitives.
 *
 * No new cryptography lives here: the emergency credential itself is built by
 * the same keyring derivation as the owner's phrase (see
 * src/vault/operations/onboarding.ts `deriveKeyring`), the phrase capsule
 * reuses the standard wrap-for-user KEM path, and the binding signature follows
 * the length-framed canonical-payload pattern of key-registration.ts.
 *
 * The binding signature (grantor identity key, dedicated context) covers every
 * parameter of an escrow: who it targets (pinned contact identity), the wait
 * time, when it was created, WHICH credential it arms (hash of the auth
 * verifier, which itself is never released to clients) and WHAT the contact
 * will receive (hash of the capsule). The grantor's devices audit their escrow
 * list against it; the contact verifies it at reveal time against the grantor
 * identity pinned in their own TOFU registry; the server verifies it at write.
 */
import sodium from 'libsodium-wrappers-sumo';

import {
  type HybridPublicKey,
  type HybridSecretKey,
  decryptSymmetricKeyForUser,
  encryptSymmetricKeyForUsers,
  ensureSodium,
  writeUint16LE,
  writeUint32LE,
} from '@encryption/src/crypto/encryption';
import { type SignaturePublicKey, type SignatureSecretKey, signDetached, verifyDetached } from '@encryption/src/crypto/signature';

const ESCROW_DOMAIN = 'lasuite-encryption/emergency-escrow/v1';

export interface EmergencyEscrowRecord {
  /** INTERNAL user ids (users.id), never OIDC subs (same rationale as key-registration.ts). */
  grantorUserId: string;
  granteeUserId: string;
  /** Contact identity wire blob [version:1][ed25519:32], pinned at designation. */
  granteeIdentityPublicKeyWire: Uint8Array;
  /** Opposition window in days; inside the signature so the server cannot shorten it undetected. */
  waitTimeDays: number;
  /** Client-asserted creation time, signed verbatim. */
  escrowCreatedAtMillis: number;
  /** SHA-256 of the emergency credential's RAW auth verifier (the verifier itself is never released). */
  credentialAuthPublicKeyHash: Uint8Array;
  /** SHA-256 of the raw capsule bytes (the wrapped emergency-phrase entropy). */
  capsuleHash: Uint8Array;
}

function writeUint64LE(value: number): Uint8Array {
  const buf = new ArrayBuffer(8);
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

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  await ensureSodium();

  return sodium.crypto_hash_sha256(bytes);
}

/**
 * Build the canonical byte string the escrow binding signature covers. Both
 * the signer and every verifier must produce identical bytes for the same
 * record.
 */
export function encodeEmergencyEscrowPayload(record: EmergencyEscrowRecord): Uint8Array {
  const encoder = new TextEncoder();

  return concat([
    ...lengthPrefixed(encoder.encode(ESCROW_DOMAIN)),
    ...lengthPrefixed(encoder.encode(record.grantorUserId)),
    ...lengthPrefixed(encoder.encode(record.granteeUserId)),
    ...lengthPrefixed(record.granteeIdentityPublicKeyWire),
    writeUint32LE(record.waitTimeDays),
    writeUint64LE(record.escrowCreatedAtMillis),
    ...lengthPrefixed(record.credentialAuthPublicKeyHash),
    ...lengthPrefixed(record.capsuleHash),
  ]);
}

export async function signEmergencyEscrow(record: EmergencyEscrowRecord, identitySecretKey: SignatureSecretKey): Promise<Uint8Array> {
  return signDetached(encodeEmergencyEscrowPayload(record), identitySecretKey);
}

/** Fail-safe: malformed inputs return false, never throw. `identityPublicKey` is the RAW Ed25519 key. */
export async function verifyEmergencyEscrow(
  record: EmergencyEscrowRecord,
  signature: Uint8Array,
  identityPublicKey: SignaturePublicKey
): Promise<boolean> {
  try {
    return await verifyDetached(signature, encodeEmergencyEscrowPayload(record), identityPublicKey);
  } catch {
    return false;
  }
}

/**
 * Wrap the 32-byte emergency-phrase entropy to the contact's X-Wing public
 * key. Exactly the wire format of `encryptSymmetricKeyForUsers` (the entropy
 * has the same size and secrecy profile as a symmetric key), so the contact
 * opens it with the standard unwrap path.
 */
export async function wrapPhraseEntropyForGrantee(phraseEntropy: Uint8Array, granteePublicKey: HybridPublicKey): Promise<Uint8Array> {
  const wrapped = await encryptSymmetricKeyForUsers(phraseEntropy, { grantee: granteePublicKey });

  return wrapped.grantee;
}

/**
 * Open a capsule with the contact's key history, newest first: the vault's key
 * history is grow-only, so a capsule wrapped to an older (since-rotated) key
 * still opens with the retained older secret. Throws the underlying
 * WRONG_SECRET_KEY error when no key matches.
 */
export async function unwrapPhraseEntropy(capsule: Uint8Array, granteeSecretKeys: HybridSecretKey[]): Promise<Uint8Array> {
  let lastError: unknown = new Error('WRONG_SECRET_KEY');

  for (const secretKey of granteeSecretKeys) {
    try {
      return await decryptSymmetricKeyForUser(secretKey, capsule);
    } catch (err) {
      lastError = err;
    }
  }

  throw lastError;
}
