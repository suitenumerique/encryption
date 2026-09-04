/**
 * The synchronized vault state and its merge.
 *
 * The state carries every encryption key version and identity generation
 * (grow-only, immutable, so they can only be unioned and never conflict) plus
 * the TOFU trust map (the only mutable data). The merge is a join over a total
 * order per record, which makes it commutative, associative, and idempotent:
 * every device converges to the same state regardless of sync order, and the
 * re-pull-merge-retry loop after a 409 is always safe to repeat.
 *
 * Conflicts can only happen on a TOFU entry (two devices deciding differently
 * about the same contact). The tie-break is fail-safe: a refusal or a detected
 * mismatch never loses to an equally-recent trust.
 */
import { z } from 'zod';

import '@encryption/src/shared/zod-jitless';

export const VAULT_SCHEMA_VERSION = 1;

// 'unknown' is a real, persisted state: a contact seen (their fingerprint
// recorded) but not yet explicitly verified. It records the fingerprint so a
// LATER change is detectable as a mismatch, without marking the contact trusted.
// Sharing to an 'unknown' contact is allowed; only a mismatch or a 'refused'
// blocks. Trust ('trusted') / refusal ('refused') come only from an explicit user
// decision.
export const tofuStatusSchema = z.enum(['unknown', 'trusted', 'refused']);
export type TofuStatus = z.infer<typeof tofuStatusSchema>;

/** An identity (signature) key generation. Immutable once minted. */
export const identityEntrySchema = z.object({
  generation: z.number(),
  algo: z.string(),
  signaturePublicKey: z.string(), // base64 wire blob
  signatureSecretKey: z.string(), // base64
  createdAt: z.number(), // epoch ms
});
export type IdentityEntry = z.infer<typeof identityEntrySchema>;

/** An encryption key version. Immutable once minted; old ones are kept to decrypt. */
export const encryptionKeyEntrySchema = z.object({
  version: z.number(),
  algo: z.string(),
  publicKey: z.string(), // base64 wire blob
  secretKey: z.string(), // base64
  createdAt: z.number(), // epoch ms
});
export type EncryptionKeyEntry = z.infer<typeof encryptionKeyEntrySchema>;

/** A trust decision about one remote user, keyed by their userId in the map. */
export const tofuEntrySchema = z.object({
  fingerprint: z.string(),
  status: tofuStatusSchema,
  deleted: z.boolean(), // tombstone, so a delete propagates and can't be resurrected
  revisionDate: z.number(), // epoch ms, drives last-write-wins
});
export type TofuEntry = z.infer<typeof tofuEntrySchema>;

export const activePointerSchema = z.object({ identityGen: z.number(), encKeyVersion: z.number() });

export const vaultStateSchema = z.object({
  schema: z.number(),
  identities: z.array(identityEntrySchema), // keyed by generation, ascending
  encryptionKeys: z.array(encryptionKeyEntrySchema), // keyed by version, ascending
  active: activePointerSchema,
  tofu: z.record(z.string(), tofuEntrySchema),
});
export type VaultState = z.infer<typeof vaultStateSchema>;

export function emptyVaultState(): VaultState {
  return { schema: VAULT_SCHEMA_VERSION, identities: [], encryptionKeys: [], active: { identityGen: 0, encKeyVersion: 0 }, tofu: {} };
}

// ---------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------

export function mergeVaultState(a: VaultState, b: VaultState): VaultState {
  return {
    schema: VAULT_SCHEMA_VERSION,
    identities: unionByKey(a.identities, b.identities, (e) => e.generation),
    encryptionKeys: unionByKey(a.encryptionKeys, b.encryptionKeys, (e) => e.version),
    active: {
      identityGen: Math.max(a.active.identityGen, b.active.identityGen),
      encKeyVersion: Math.max(a.active.encKeyVersion, b.active.encKeyVersion),
    },
    tofu: mergeTofu(a.tofu, b.tofu),
  };
}

/**
 * Union two grow-only lists keyed by a monotonic number. Entries are immutable,
 * so a key collision means identical content; if the server ever handed back a
 * divergent duplicate we pick deterministically (largest serialization) so the
 * merge stays a well-defined join rather than depending on argument order.
 */
function unionByKey<T>(a: T[], b: T[], key: (e: T) => number): T[] {
  const byKey = new Map<number, T>();

  for (const e of [...a, ...b]) {
    const k = key(e);
    const existing = byKey.get(k);
    if (existing === undefined || JSON.stringify(e) > JSON.stringify(existing)) {
      byKey.set(k, e);
    }
  }

  return [...byKey.keys()].sort((x, y) => x - y).map((k) => byKey.get(k)!);
}

function mergeTofu(a: Record<string, TofuEntry>, b: Record<string, TofuEntry>): Record<string, TofuEntry> {
  const out: Record<string, TofuEntry> = {};

  for (const userId of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const x = a[userId];
    const y = b[userId];
    out[userId] = x === undefined ? y : y === undefined ? x : winningTofu(x, y);
  }

  return out;
}

/**
 * Fail-safe last-write-wins. The comparison key is a full tuple so any two
 * distinct entries compare unequal, which is what makes the merge a total-order
 * join (commutative + associative + idempotent). Priority, highest first: newer
 * revisionDate, then the stronger status (refused > trusted > unknown, so an
 * explicit decision beats a bare first-sight record and a refusal is never lost),
 * then a tombstone, then higher fingerprint.
 */
function winningTofu(x: TofuEntry, y: TofuEntry): TofuEntry {
  const rank = (s: TofuStatus): number => (s === 'refused' ? 2 : s === 'trusted' ? 1 : 0);
  const key = (e: TofuEntry): [number, number, number, string] => [e.revisionDate, rank(e.status), e.deleted ? 1 : 0, e.fingerprint];

  const kx = key(x);
  const ky = key(y);

  for (let i = 0; i < kx.length; i++) {
    if (kx[i] === ky[i]) continue;
    return kx[i] > ky[i] ? x : y;
  }

  return x;
}

// ---------------------------------------------------------------------------
// Local mutations (immutable, return a new state)
// ---------------------------------------------------------------------------

export function setTofu(state: VaultState, remoteUserId: string, fingerprint: string, status: TofuStatus, now: number): VaultState {
  return { ...state, tofu: { ...state.tofu, [remoteUserId]: { fingerprint, status, deleted: false, revisionDate: now } } };
}

export function deleteTofu(state: VaultState, remoteUserId: string, now: number): VaultState {
  const prev = state.tofu[remoteUserId];
  if (!prev) return state;

  return { ...state, tofu: { ...state.tofu, [remoteUserId]: { ...prev, deleted: true, revisionDate: now } } };
}

export function addIdentity(state: VaultState, entry: IdentityEntry): VaultState {
  const identities = unionByKey(state.identities, [entry], (e) => e.generation);

  return { ...state, identities, active: { ...state.active, identityGen: Math.max(state.active.identityGen, entry.generation) } };
}

export function addEncryptionKey(state: VaultState, entry: EncryptionKeyEntry): VaultState {
  const encryptionKeys = unionByKey(state.encryptionKeys, [entry], (e) => e.version);

  return { ...state, encryptionKeys, active: { ...state.active, encKeyVersion: Math.max(state.active.encKeyVersion, entry.version) } };
}

export function activeIdentity(state: VaultState): IdentityEntry | undefined {
  return state.identities.find((e) => e.generation === state.active.identityGen);
}

export function activeEncryptionKey(state: VaultState): EncryptionKeyEntry | undefined {
  return state.encryptionKeys.find((e) => e.version === state.active.encKeyVersion);
}

export function encryptionKeyByVersion(state: VaultState, version: number): EncryptionKeyEntry | undefined {
  return state.encryptionKeys.find((e) => e.version === version);
}

// ---------------------------------------------------------------------------
// Change detection
// ---------------------------------------------------------------------------

// Sorts explicitly rather than trusting insertion order: `identities` and
// `encryptionKeys` come out of `unionByKey` ordered, but a state rebuilt from a
// different merge order would otherwise compare unequal while being identical.
function canonicalKeyMaterial(state: VaultState): string {
  return JSON.stringify({
    identities: [...state.identities].sort((a, b) => a.generation - b.generation),
    encryptionKeys: [...state.encryptionKeys].sort((a, b) => a.version - b.version),
    active: state.active,
  });
}

/**
 * Whether the user's own key material (identities, encryption keys, active
 * pointer) differs between two states. Deliberately blind to `tofu`: trust
 * decisions live in the same vault but are an interface concern, and a change
 * there is not a key change for anyone listening.
 */
export function keyMaterialChanged(before: VaultState, after: VaultState): boolean {
  return canonicalKeyMaterial(before) !== canonicalKeyMaterial(after);
}
