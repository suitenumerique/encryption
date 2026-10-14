/**
 * The signed manifest: the vault's integrity anchor.
 *
 * It is a versioned index of every stored item, each pinned by a hash of its
 * ciphertext, signed by the identity key. A consuming device verifies the
 * signature against the identity it already trusts (not one the server labels),
 * checks that every item it received is covered, and refuses any revision below
 * the highest it has already seen. That detects a server that splices, drops,
 * swaps, or rolls back items, without trusting the server for integrity.
 */
import sodium from 'libsodium-wrappers-sumo';
import { z } from 'zod';

import { concat, ensureSodium, lengthPrefixed, writeUint32LE, writeUint64LE } from '@encryption/src/crypto/encryption';
import { base64ToUint8, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { type SignaturePublicKey, type SignatureSecretKey, signDetached, verifyDetached } from '@encryption/src/crypto/signature';
import { itemTypeSchema } from '@encryption/src/crypto/vault-items';
import { DOMAIN_VAULT_MANIFEST } from '@encryption/src/shared/crypto-domains';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import '@encryption/src/shared/zod-jitless';

// Algorithms are named in the manifest rather than implied, so a verifier never
// has to guess what produced a value: each item hash carries its algorithm as a
// prefix, and the manifest states which algorithm signs it. Both are inside the
// signed bytes, so neither can be swapped for a weaker one undetected.
export const MANIFEST_SIGNATURE_ALGORITHM = 'ed25519';
const CONTENT_HASH_PREFIX = 'blake2b-256:';
// The prefix, then 32 bytes in padded standard base64 (what `hashCiphertext` emits).
const CONTENT_HASH_PATTERN = /^blake2b-256:[A-Za-z0-9+/]{43}=$/;

export const sealedItemSchema = z.object({
  id: z.string(),
  type: itemTypeSchema,
  revisionDate: z.number(),
  ciphertext: z.string(), // base64
});
export type SealedItem = z.infer<typeof sealedItemSchema>;

export const manifestItemSchema = z.object({
  id: z.string(),
  type: itemTypeSchema,
  contentHash: z.string().regex(CONTENT_HASH_PATTERN), // `blake2b-256:` + base64 BLAKE2b-256 of the ciphertext bytes
  revisionDate: z.number().int().nonnegative(),
});
export type ManifestItem = z.infer<typeof manifestItemSchema>;

// Signed as 32-bit integers (see manifestBytes), so refused beyond that at parse time.
const counter = z.number().int().nonnegative().max(0xffffffff);

export const vaultManifestSchema = z.object({
  schema: counter,
  signatureAlgorithm: z.literal(MANIFEST_SIGNATURE_ALGORITHM),
  revision: counter,
  identityGen: counter,
  items: z.array(manifestItemSchema),
});
export type VaultManifest = z.infer<typeof vaultManifestSchema>;

export const MANIFEST_SCHEMA_VERSION = 1;

/**
 * Parse untrusted (server-supplied) manifest JSON. Returns null on any malformed
 * input, so a bad shape fails closed exactly like a bad signature.
 *
 * NOTE on forward compatibility: `itemTypeSchema` is a STRICT enum, so a manifest
 * that a newer client wrote with a new item type fails this parse on an older
 * client and surfaces to the sync engine as `integrity-error` (indistinguishable
 * from tampering) until the old client updates. That is a deliberate strictness
 * tradeoff, not an oversight: adding a new item type is therefore NOT a
 * transparent change, it needs a real cross-version rollout plan (ship the parser
 * that tolerates the new type to all clients BEFORE any client starts writing it).
 * The producing client is always the up-to-date one; the failing device is the
 * stale one. If we ever want to detect and act on that automatically, the clean
 * hook is: verify the manifest SIGNATURE over the raw bytes FIRST, and only when
 * it verifies against the trusted identity treat a subsequent parse failure as
 * "authentic but newer" (trigger a non-blocking distant-version check, no waiting,
 * and no-op offline) rather than as tampering. Not wired up: it should not happen
 * in normal operation.
 */
export function parseManifest(json: string): VaultManifest | null {
  try {
    return vaultManifestSchema.parse(JSON.parse(json));
  } catch {
    return null;
  }
}

export function hashCiphertext(ciphertextBase64: string): string {
  return `${CONTENT_HASH_PREFIX}${uint8ToBase64(sodium.crypto_generichash(32, base64ToUint8(ciphertextBase64), null))}`;
}

export function buildManifest(revision: number, identityGen: number, items: SealedItem[]): VaultManifest {
  const manifestItems = items
    .map((i) => ({ id: i.id, type: i.type, contentHash: hashCiphertext(i.ciphertext), revisionDate: i.revisionDate }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  return { schema: MANIFEST_SCHEMA_VERSION, signatureAlgorithm: MANIFEST_SIGNATURE_ALGORITHM, revision, identityGen, items: manifestItems };
}

/**
 * The bytes the identity key signs, framed like the other signed messages: each
 * text field preceded by its 16-bit length, counters as 32-bit and millisecond
 * timestamps as 64-bit little-endian integers, the item count before the items.
 * Nothing depends on how a field is spelled, so no two manifests share these
 * bytes, and the leading domain label keeps any other message the identity key
 * signs from reading as a manifest.
 */
export function manifestBytes(manifest: VaultManifest): Uint8Array {
  const text = (value: string) => lengthPrefixed(sodium.from_string(value));

  return concat([
    ...text(DOMAIN_VAULT_MANIFEST),
    writeUint32LE(manifest.schema),
    ...text(manifest.signatureAlgorithm),
    writeUint32LE(manifest.revision),
    writeUint32LE(manifest.identityGen),
    writeUint32LE(manifest.items.length),
    ...manifest.items.flatMap((item) => [...text(item.id), ...text(item.type), ...text(item.contentHash), writeUint64LE(item.revisionDate)]),
  ]);
}

export async function signManifest(manifest: VaultManifest, identitySecretKey: SignatureSecretKey): Promise<string> {
  await ensureSodium();

  return uint8ToBase64(await signDetached(manifestBytes(manifest), identitySecretKey));
}

export async function verifyManifest(manifest: VaultManifest, signatureBase64: string, identityPublicKey: SignaturePublicKey): Promise<boolean> {
  await ensureSodium();

  // A field too long to frame cannot have been signed, and a signature that is
  // not base64 is not a signature: refuse both like a bad signature.
  let bytes: Uint8Array;
  let signature: Uint8Array;
  try {
    bytes = manifestBytes(manifest);
    signature = base64ToUint8(signatureBase64);
  } catch (err) {
    if (err instanceof VaultError && (err.code === VaultErrorCode.INVALID_CANONICAL_PAYLOAD || err.code === VaultErrorCode.MALFORMED_BASE64))
      return false;
    throw err;
  }

  return verifyDetached(signature, bytes, identityPublicKey);
}

/**
 * Every received item must appear in the manifest with a matching ciphertext
 * hash and revision, and the manifest must list nothing extra. Fails closed.
 */
export function sealedItemsMatchManifest(items: SealedItem[], manifest: VaultManifest): boolean {
  if (items.length !== manifest.items.length) return false;

  const expected = new Map(manifest.items.map((i) => [i.id, i]));

  for (const item of items) {
    const m = expected.get(item.id);
    if (!m) return false;
    if (m.contentHash !== hashCiphertext(item.ciphertext)) return false;
    if (m.revisionDate !== item.revisionDate) return false;
    if (m.type !== item.type) return false;
  }

  return true;
}

export function isRollback(revision: number, lastSeenRevision: number): boolean {
  return revision < lastSeenRevision;
}
