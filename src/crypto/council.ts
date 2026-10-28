/**
 * The recovery council's signed records and wraps (shamir.md).
 *
 * - A **roster version** lists a council's custodians (slot, user id, pinned
 *   identity key) and its threshold. Version 1 is signed by every custodian it
 *   names, each vouching for their own key; every later version by `k` custodians
 *   of the previous one plus every custodian it adds or re-keys. Users verify that
 *   chain, so the server alone can never put a key of its own in a council.
 * - A user's **escrow** splits the entropy of a dormant emergency phrase between
 *   the custodians of one roster version; the user's identity signs what was
 *   split (Pedersen commitments and a hash, never the secret) and over which
 *   roster.
 * - A **contribution** is one custodian handing their share to a recovery,
 *   wrapped for the locked-out browser's ephemeral key, signed by the custodian.
 * - A **resharing** moves escrows to a new roster version without the users: each
 *   helper seals sub-shares under a transfer key it wraps for each new custodian
 *   and signs, so a new custodian accepts only sub-shares from a real helper, and
 *   signs the commitments those sub-shares verify against.
 *
 * Every encoding is length-framed after its domain label, like the other signed
 * records (key-registration.ts, emergency-escrow.ts).
 */
import sodium from 'libsodium-wrappers-sumo';

import {
  type HybridPublicKey,
  type HybridSecretKey,
  concat,
  decryptContent,
  decryptSymmetricKeyForUser,
  encryptContent,
  encryptSymmetricKeyForUsers,
  ensureSodium,
  lengthPrefixed,
  writeUint32LE,
  writeUint64LE,
} from '@encryption/src/crypto/encryption';
import { type SignatureSecretKey, signDetached, verifyDetached } from '@encryption/src/crypto/signature';
import {
  DOMAIN_COUNCIL_CONTRIBUTION,
  DOMAIN_COUNCIL_ESCROW,
  DOMAIN_COUNCIL_FINGERPRINT,
  DOMAIN_COUNCIL_REQUEST_FINGERPRINT,
  DOMAIN_COUNCIL_RESHARE_COMMITMENTS,
  DOMAIN_COUNCIL_RESHARE_KEY_BINDING,
  DOMAIN_COUNCIL_ROSTER,
  DOMAIN_COUNCIL_SECRET_COMMITMENT,
  DOMAIN_COUNCIL_SUBSHARE,
  DOMAIN_KEM_COUNCIL_RESHARE_KEY,
  DOMAIN_KEM_COUNCIL_SHARE,
  DOMAIN_KEM_COUNCIL_TRANSFER,
} from '@encryption/src/shared/crypto-domains';
import { computeDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

const text = (value: string) => new TextEncoder().encode(value);

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  await ensureSodium();

  return sodium.crypto_hash_sha256(bytes);
}

/** The raw Ed25519 key inside an identity wire blob `[version:1][ed25519:32]`. */
export function rawIdentityKey(identityPublicKeyWire: Uint8Array): Uint8Array {
  return identityPublicKeyWire.slice(1);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

// ----- Roster ---------------------------------------------------------------

export interface RosterMember {
  slot: number;
  userId: string;
  /** Identity wire blob `[version:1][ed25519:32]`, pinned when the version was proposed. */
  identityPublicKeyWire: Uint8Array;
}

export interface RosterRecord {
  councilId: string;
  version: number;
  threshold: number;
  /** SHA-256 of the previous version's payload, empty for version 1. */
  previousRosterHash: Uint8Array;
  members: RosterMember[];
}

function sortedMembers(members: RosterMember[]): RosterMember[] {
  return [...members].sort((a, b) => a.slot - b.slot);
}

export function encodeRosterPayload(record: RosterRecord): Uint8Array {
  const members = sortedMembers(record.members);

  return concat([
    ...lengthPrefixed(text(DOMAIN_COUNCIL_ROSTER)),
    ...lengthPrefixed(text(record.councilId)),
    writeUint32LE(record.version),
    writeUint32LE(record.threshold),
    ...lengthPrefixed(record.previousRosterHash),
    writeUint32LE(members.length),
    ...members.flatMap((member) => [
      writeUint32LE(member.slot),
      ...lengthPrefixed(text(member.userId)),
      ...lengthPrefixed(member.identityPublicKeyWire),
    ]),
  ]);
}

export function rosterHash(record: RosterRecord): Promise<Uint8Array> {
  return sha256(encodeRosterPayload(record));
}

/** The 40 digits an organization publishes for a roster version and its users compare. */
export function rosterFingerprint(record: RosterRecord): Promise<string> {
  return computeDecimalFingerprint(DOMAIN_COUNCIL_FINGERPRINT, encodeRosterPayload(record));
}

export function signRoster(record: RosterRecord, identitySecretKey: SignatureSecretKey): Promise<Uint8Array> {
  return signDetached(encodeRosterPayload(record), identitySecretKey);
}

export async function verifyRosterSignature(record: RosterRecord, signature: Uint8Array, identityPublicKeyWire: Uint8Array): Promise<boolean> {
  try {
    return await verifyDetached(signature, encodeRosterPayload(record), rawIdentityKey(identityPublicKeyWire));
  } catch {
    return false;
  }
}

export interface SignedRosterVersion {
  record: RosterRecord;
  /** Signatures by identity keys; each is matched against the members that may sign. */
  signatures: Array<{ identityPublicKeyWire: Uint8Array; signature: Uint8Array }>;
}

/** Who signed a version among `candidates`, by identity key, counting each member once. */
async function signersAmong(version: SignedRosterVersion, candidates: RosterMember[]): Promise<Set<number>> {
  const signed = new Set<number>();

  for (const candidate of candidates) {
    for (const entry of version.signatures) {
      if (!equalBytes(entry.identityPublicKeyWire, candidate.identityPublicKeyWire)) continue;
      if (await verifyRosterSignature(version.record, entry.signature, candidate.identityPublicKeyWire)) {
        signed.add(candidate.slot);
        break;
      }
    }
  }

  return signed;
}

function wellFormed(record: RosterRecord): boolean {
  const slots = new Set(record.members.map((m) => m.slot));
  const users = new Set(record.members.map((m) => m.userId));

  return (
    record.members.length >= 1 &&
    slots.size === record.members.length &&
    users.size === record.members.length &&
    record.members.every((m) => Number.isInteger(m.slot) && m.slot >= 1 && m.slot <= 255) &&
    Number.isInteger(record.threshold) &&
    record.threshold >= 1 &&
    record.threshold <= record.members.length
  );
}

/** A member whose slot did not exist in `previous` with that same identity: they must vouch for their own key. */
function isNewcomer(member: RosterMember, previous: RosterRecord): boolean {
  const before = previous.members.find((m) => m.slot === member.slot);

  return !before || before.userId !== member.userId || !equalBytes(before.identityPublicKeyWire, member.identityPublicKeyWire);
}

export type RosterChainResult = { ok: true; head: RosterRecord; headHash: Uint8Array } | { ok: false; reason: string; brokenAtVersion: number };

/**
 * Verify a chain of roster versions, oldest first.
 *
 * `trustedHash` anchors it: the hash of a version the caller already trusts (the
 * one a user's own signed escrow names). Without it, the chain must start at
 * version 1, which every member it names must have signed.
 *
 * A slot number is never given to another person or key later in the chain:
 * shares of a departed custodian stay on their slot's point of the polynomial
 * until a resharing, and giving that point to a newcomer would be a handover.
 */
export async function verifyRosterChain(chain: SignedRosterVersion[], trustedHash?: Uint8Array): Promise<RosterChainResult> {
  if (chain.length === 0) return { ok: false, reason: 'empty', brokenAtVersion: 0 };

  let start = 0;

  if (trustedHash) {
    const hashes = await Promise.all(chain.map((v) => rosterHash(v.record)));
    start = hashes.findIndex((hash) => equalBytes(hash, trustedHash));
    if (start === -1) return { ok: false, reason: 'anchor-not-found', brokenAtVersion: 0 };
  } else {
    const genesis = chain[0];
    if (genesis.record.version !== 1 || genesis.record.previousRosterHash.length !== 0 || !wellFormed(genesis.record))
      return { ok: false, reason: 'bad-genesis', brokenAtVersion: genesis.record.version };

    const signed = await signersAmong(genesis, genesis.record.members);
    if (signed.size !== genesis.record.members.length) return { ok: false, reason: 'genesis-unsigned', brokenAtVersion: 1 };
  }

  const slotOwner = new Map<number, string>();
  const remember = (record: RosterRecord) => {
    for (const m of record.members) slotOwner.set(m.slot, `${m.userId}|${uint8Hex(m.identityPublicKeyWire)}`);
  };

  remember(chain[start].record);

  for (let i = start + 1; i < chain.length; i++) {
    const previous = chain[i - 1].record;
    const current = chain[i];
    const record = current.record;

    if (record.councilId !== previous.councilId || record.version !== previous.version + 1 || !wellFormed(record))
      return { ok: false, reason: 'bad-version', brokenAtVersion: record.version };
    if (!equalBytes(record.previousRosterHash, await rosterHash(previous))) return { ok: false, reason: 'bad-link', brokenAtVersion: record.version };

    for (const member of record.members) {
      const owner = slotOwner.get(member.slot);
      if (owner !== undefined && owner !== `${member.userId}|${uint8Hex(member.identityPublicKeyWire)}`)
        return { ok: false, reason: 'slot-reused', brokenAtVersion: record.version };
    }

    const quorum = await signersAmong(current, previous.members);
    if (quorum.size < previous.threshold) return { ok: false, reason: 'no-quorum', brokenAtVersion: record.version };

    const newcomers = record.members.filter((m) => isNewcomer(m, previous));
    const vouched = await signersAmong(current, newcomers);
    if (vouched.size !== newcomers.length) return { ok: false, reason: 'newcomer-unsigned', brokenAtVersion: record.version };

    remember(record);
  }

  const head = chain[chain.length - 1].record;

  return { ok: true, head, headHash: await rosterHash(head) };
}

function uint8Hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ----- Commitments ----------------------------------------------------------

/** Commitment to the emergency secret itself, checked after combining (cheap, unlike re-deriving the credential). */
export function secretCommitment(userId: string, councilId: string, secret: Uint8Array): Promise<Uint8Array> {
  return sha256(
    concat([
      ...lengthPrefixed(text(DOMAIN_COUNCIL_SECRET_COMMITMENT)),
      ...lengthPrefixed(text(userId)),
      ...lengthPrefixed(text(councilId)),
      ...lengthPrefixed(secret),
    ])
  );
}

// ----- Escrow ---------------------------------------------------------------

export interface EscrowShareEntry {
  slot: number;
  capsuleHash: Uint8Array;
}

export interface CouncilEscrowRecord {
  userId: string;
  councilId: string;
  rosterVersion: number;
  rosterHash: Uint8Array;
  threshold: number;
  escrowCreatedAtMillis: number;
  /** SHA-256 of the dormant credential's auth verifier (the verifier itself never leaves the server). */
  credentialAuthPublicKeyHash: Uint8Array;
  secretCommitment: Uint8Array;
  /** Pedersen commitments of the split (src/crypto/shamir.ts), encoded. */
  shareCommitments: Uint8Array;
  shares: EscrowShareEntry[];
}

export function encodeEscrowPayload(record: CouncilEscrowRecord): Uint8Array {
  const shares = [...record.shares].sort((a, b) => a.slot - b.slot);

  return concat([
    ...lengthPrefixed(text(DOMAIN_COUNCIL_ESCROW)),
    ...lengthPrefixed(text(record.userId)),
    ...lengthPrefixed(text(record.councilId)),
    writeUint32LE(record.rosterVersion),
    ...lengthPrefixed(record.rosterHash),
    writeUint32LE(record.threshold),
    writeUint64LE(record.escrowCreatedAtMillis),
    ...lengthPrefixed(record.credentialAuthPublicKeyHash),
    ...lengthPrefixed(record.secretCommitment),
    ...lengthPrefixed(record.shareCommitments),
    writeUint32LE(shares.length),
    ...shares.flatMap((share) => [writeUint32LE(share.slot), ...lengthPrefixed(share.capsuleHash)]),
  ]);
}

export function signEscrow(record: CouncilEscrowRecord, identitySecretKey: SignatureSecretKey): Promise<Uint8Array> {
  return signDetached(encodeEscrowPayload(record), identitySecretKey);
}

/** Fail-safe: malformed input returns false. `identityPublicKeyWire` is the wire blob. */
export async function verifyEscrow(record: CouncilEscrowRecord, signature: Uint8Array, identityPublicKeyWire: Uint8Array): Promise<boolean> {
  try {
    return await verifyDetached(signature, encodeEscrowPayload(record), rawIdentityKey(identityPublicKeyWire));
  } catch {
    return false;
  }
}

export async function capsuleHash(capsule: Uint8Array): Promise<Uint8Array> {
  return sha256(capsule);
}

// ----- Contribution ---------------------------------------------------------

export interface ContributionRecord {
  requestId: string;
  userId: string;
  councilId: string;
  slot: number;
  custodianUserId: string;
  ephemeralPublicKeyHash: Uint8Array;
  /** SHA-256 over the wrapped shares handed over, one per escrow generation, in order. */
  wrappedSharesHash: Uint8Array;
  inPerson: boolean;
}

export function encodeContributionPayload(record: ContributionRecord): Uint8Array {
  return concat([
    ...lengthPrefixed(text(DOMAIN_COUNCIL_CONTRIBUTION)),
    ...lengthPrefixed(text(record.requestId)),
    ...lengthPrefixed(text(record.userId)),
    ...lengthPrefixed(text(record.councilId)),
    writeUint32LE(record.slot),
    ...lengthPrefixed(text(record.custodianUserId)),
    ...lengthPrefixed(record.ephemeralPublicKeyHash),
    ...lengthPrefixed(record.wrappedSharesHash),
    Uint8Array.of(record.inPerson ? 1 : 0),
  ]);
}

export function signContribution(record: ContributionRecord, identitySecretKey: SignatureSecretKey): Promise<Uint8Array> {
  return signDetached(encodeContributionPayload(record), identitySecretKey);
}

export async function verifyContribution(record: ContributionRecord, signature: Uint8Array, identityPublicKeyWire: Uint8Array): Promise<boolean> {
  try {
    return await verifyDetached(signature, encodeContributionPayload(record), rawIdentityKey(identityPublicKeyWire));
  } catch {
    return false;
  }
}

export async function wrappedSharesHash(wrappedShares: Uint8Array[]): Promise<Uint8Array> {
  return sha256(concat(wrappedShares.flatMap(lengthPrefixed)));
}

export function ephemeralKeyHash(ephemeralPublicKeyWire: Uint8Array): Promise<Uint8Array> {
  return sha256(ephemeralPublicKeyWire);
}

/** The 40 digits (and QR) a locked-out browser shows the custodian at the meeting. */
export function requestFingerprint(ephemeralPublicKeyWire: Uint8Array): Promise<string> {
  return computeDecimalFingerprint(DOMAIN_COUNCIL_REQUEST_FINGERPRINT, ephemeralPublicKeyWire);
}

// ----- Wraps ----------------------------------------------------------------

async function wrapFor(bytes: Uint8Array, publicKey: HybridPublicKey, domain: typeof DOMAIN_KEM_COUNCIL_SHARE | typeof DOMAIN_KEM_COUNCIL_TRANSFER) {
  return (await encryptSymmetricKeyForUsers(bytes, { recipient: publicKey }, domain)).recipient;
}

/** Newest key first: a share wrapped before a key rotation still opens with the retained older secret. */
async function unwrapWithAny(
  wrapped: Uint8Array,
  secretKeys: HybridSecretKey[],
  domain: typeof DOMAIN_KEM_COUNCIL_SHARE | typeof DOMAIN_KEM_COUNCIL_TRANSFER | typeof DOMAIN_KEM_COUNCIL_RESHARE_KEY
) {
  let lastError: unknown = new Error('WRONG_SECRET_KEY');

  for (const secretKey of secretKeys) {
    try {
      return await decryptSymmetricKeyForUser(secretKey, wrapped, domain);
    } catch (err) {
      lastError = err;
    }
  }

  throw lastError;
}

/** A capsule: one encoded share wrapped for its custodian's encryption key. */
export function wrapShareForCustodian(encodedShare: Uint8Array, custodianPublicKey: HybridPublicKey): Promise<Uint8Array> {
  return wrapFor(encodedShare, custodianPublicKey, DOMAIN_KEM_COUNCIL_SHARE);
}

export function unwrapCapsule(capsule: Uint8Array, custodianSecretKeys: HybridSecretKey[]): Promise<Uint8Array> {
  return unwrapWithAny(capsule, custodianSecretKeys, DOMAIN_KEM_COUNCIL_SHARE);
}

/** A share handed to a recovery, wrapped for the locked-out browser's ephemeral key. */
export function wrapShareForRequest(encodedShare: Uint8Array, ephemeralPublicKey: HybridPublicKey): Promise<Uint8Array> {
  return wrapFor(encodedShare, ephemeralPublicKey, DOMAIN_KEM_COUNCIL_TRANSFER);
}

export function unwrapRequestShare(wrapped: Uint8Array, ephemeralSecretKey: HybridSecretKey): Promise<Uint8Array> {
  return unwrapWithAny(wrapped, [ephemeralSecretKey], DOMAIN_KEM_COUNCIL_TRANSFER);
}

// ----- Resharing ------------------------------------------------------------

export interface ReshareKeyBindingRecord {
  sessionId: string;
  councilId: string;
  targetRosterVersion: number;
  helperSlot: number;
  recipientSlot: number;
  wrappedTransferKeyHash: Uint8Array;
}

export function encodeReshareKeyBinding(record: ReshareKeyBindingRecord): Uint8Array {
  return concat([
    ...lengthPrefixed(text(DOMAIN_COUNCIL_RESHARE_KEY_BINDING)),
    ...lengthPrefixed(text(record.sessionId)),
    ...lengthPrefixed(text(record.councilId)),
    writeUint32LE(record.targetRosterVersion),
    writeUint32LE(record.helperSlot),
    writeUint32LE(record.recipientSlot),
    ...lengthPrefixed(record.wrappedTransferKeyHash),
  ]);
}

export function signReshareKeyBinding(record: ReshareKeyBindingRecord, identitySecretKey: SignatureSecretKey): Promise<Uint8Array> {
  return signDetached(encodeReshareKeyBinding(record), identitySecretKey);
}

export async function verifyReshareKeyBinding(
  record: ReshareKeyBindingRecord,
  signature: Uint8Array,
  identityPublicKeyWire: Uint8Array
): Promise<boolean> {
  try {
    return await verifyDetached(signature, encodeReshareKeyBinding(record), rawIdentityKey(identityPublicKeyWire));
  } catch {
    return false;
  }
}

export interface ReshareCommitmentsRecord {
  sessionId: string;
  councilId: string;
  escrowId: string;
  targetRosterVersion: number;
  helperSlot: number;
  /** Encoded Pedersen commitments of this helper's sub-shares. */
  commitments: Uint8Array;
}

export function encodeReshareCommitments(record: ReshareCommitmentsRecord): Uint8Array {
  return concat([
    ...lengthPrefixed(text(DOMAIN_COUNCIL_RESHARE_COMMITMENTS)),
    ...lengthPrefixed(text(record.sessionId)),
    ...lengthPrefixed(text(record.councilId)),
    ...lengthPrefixed(text(record.escrowId)),
    writeUint32LE(record.targetRosterVersion),
    writeUint32LE(record.helperSlot),
    ...lengthPrefixed(record.commitments),
  ]);
}

export function signReshareCommitments(record: ReshareCommitmentsRecord, identitySecretKey: SignatureSecretKey): Promise<Uint8Array> {
  return signDetached(encodeReshareCommitments(record), identitySecretKey);
}

export async function verifyReshareCommitments(
  record: ReshareCommitmentsRecord,
  signature: Uint8Array,
  identityPublicKeyWire: Uint8Array
): Promise<boolean> {
  try {
    return await verifyDetached(signature, encodeReshareCommitments(record), rawIdentityKey(identityPublicKeyWire));
  } catch {
    return false;
  }
}

/** A fresh transfer key for one (helper, new custodian) pair of a resharing session, and its wrap. */
export async function createTransferKey(recipientPublicKey: HybridPublicKey): Promise<{ transferKey: Uint8Array; wrapped: Uint8Array }> {
  await ensureSodium();

  const transferKey = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  const wrapped = (await encryptSymmetricKeyForUsers(transferKey, { recipient: recipientPublicKey }, DOMAIN_KEM_COUNCIL_RESHARE_KEY)).recipient;

  return { transferKey, wrapped };
}

export function openTransferKey(wrapped: Uint8Array, recipientSecretKeys: HybridSecretKey[]): Promise<Uint8Array> {
  return unwrapWithAny(wrapped, recipientSecretKeys, DOMAIN_KEM_COUNCIL_RESHARE_KEY);
}

function subShareContext(sessionId: string, escrowId: string, helperSlot: number, recipientSlot: number): Uint8Array[] {
  return [text(sessionId), text(escrowId), writeUint32LE(helperSlot), writeUint32LE(recipientSlot)];
}

/** One sub-share sealed under a transfer key, bound to its session, escrow and slots. */
export function sealSubShare(
  transferKey: Uint8Array,
  subShare: Uint8Array,
  where: { sessionId: string; escrowId: string; helperSlot: number; recipientSlot: number }
): Promise<Uint8Array> {
  return encryptContent(
    subShare,
    transferKey,
    DOMAIN_COUNCIL_SUBSHARE,
    subShareContext(where.sessionId, where.escrowId, where.helperSlot, where.recipientSlot)
  );
}

export function openSubShare(
  transferKey: Uint8Array,
  sealed: Uint8Array,
  where: { sessionId: string; escrowId: string; helperSlot: number; recipientSlot: number }
): Promise<Uint8Array> {
  return decryptContent(
    sealed,
    transferKey,
    DOMAIN_COUNCIL_SUBSHARE,
    subShareContext(where.sessionId, where.escrowId, where.helperSlot, where.recipientSlot)
  );
}
