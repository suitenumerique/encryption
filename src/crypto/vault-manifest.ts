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

import { ensureSodium } from '@encryption/src/crypto/encryption';
import { base64ToUint8, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { type SignaturePublicKey, type SignatureSecretKey, signDetached, verifyDetached } from '@encryption/src/crypto/signature';
import { itemTypeSchema } from '@encryption/src/crypto/vault-items';

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
  contentHash: z.string(), // base64 BLAKE2b of the ciphertext bytes
  revisionDate: z.number(),
});
export type ManifestItem = z.infer<typeof manifestItemSchema>;

export const vaultManifestSchema = z.object({
  schema: z.number(),
  revision: z.number(),
  identityGen: z.number(),
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
  return uint8ToBase64(sodium.crypto_generichash(32, base64ToUint8(ciphertextBase64), null));
}

export function buildManifest(revision: number, identityGen: number, items: SealedItem[]): VaultManifest {
  const manifestItems = items
    .map((i) => ({ id: i.id, type: i.type, contentHash: hashCiphertext(i.ciphertext), revisionDate: i.revisionDate }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  return { schema: MANIFEST_SCHEMA_VERSION, revision, identityGen, items: manifestItems };
}

/** Deterministic bytes to sign. Hand-built so key order can never drift. */
export function manifestBytes(manifest: VaultManifest): Uint8Array {
  const items = manifest.items
    .map((i) => `${JSON.stringify(i.id)}:${JSON.stringify(i.type)}:${JSON.stringify(i.contentHash)}:${i.revisionDate}`)
    .join(',');

  return sodium.from_string(`v${manifest.schema}|${manifest.revision}|${manifest.identityGen}|[${items}]`);
}

export async function signManifest(manifest: VaultManifest, identitySecretKey: SignatureSecretKey): Promise<string> {
  await ensureSodium();

  return uint8ToBase64(await signDetached(manifestBytes(manifest), identitySecretKey));
}

export async function verifyManifest(manifest: VaultManifest, signatureBase64: string, identityPublicKey: SignaturePublicKey): Promise<boolean> {
  await ensureSodium();

  return verifyDetached(base64ToUint8(signatureBase64), manifestBytes(manifest), identityPublicKey);
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
