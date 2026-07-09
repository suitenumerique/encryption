import { z } from 'zod';

import { CompleteKeyPossessionBodySchema } from '@encryption/src/shared/schemas/key-possession';

// Wire schemas for the synchronized vault. All ciphertext / key fields are
// base64; the server never decodes them. `item_id` is a logical id such as
// "enc:2", "tofu:<userId>" or "active"; `type` is routing metadata only.

// Generous upper bounds on the opaque base64 / JSON blobs. Keys, signatures and
// wrapped VRKs are small (tens to low-hundreds of bytes); sealed items and the
// item-index manifest are larger but still modest. The caps sit well above real
// sizes so valid payloads pass, while stopping a bare z.string() from carrying a
// near-1-MiB string bounded only by the body limit.
const MAX_KEY_B64 = 1024; // Ed25519 key / signature blob
const MAX_WRAPPED_VRK_B64 = 4096; // wrapped vault root key
const MAX_DEVICE_KEY_B64 = 4096; // device public key blob
const MAX_ITEM_B64 = 128 * 1024; // sealed vault item ciphertext
const MAX_MANIFEST = 128 * 1024; // signed item-index manifest (JSON)

// The single source of truth for the item type across the client crypto layer
// (src/crypto/vault-items.ts imports this), the server, and the Prisma
// `VaultItemType` enum. The server rejects any other value.
export const VaultItemTypeSchema = z.enum(['identity', 'encryptionKey', 'tofu', 'active']);

export const VaultItemSchema = z.object({
  item_id: z.string().min(1).max(256),
  type: VaultItemTypeSchema,
  ciphertext: z.string().min(1).max(MAX_ITEM_B64),
  revision_date_millis: z.number().int().nonnegative(),
});

export type VaultItemWire = z.infer<typeof VaultItemSchema>;

export const VaultKeyringSchema = z.object({
  wrapped_vrk: z.string().min(1).max(MAX_WRAPPED_VRK_B64),
  auth_public_key: z.string().min(1).max(MAX_KEY_B64), // base64 Ed25519
  auth_pub_sig: z.string().min(1).max(MAX_KEY_B64), // base64, identity-signed binding of auth_public_key
  kdf_ops: z.number().int().positive(),
  kdf_mem: z.number().int().positive(),
  lang: z.string().min(1).max(64),
});

export type VaultKeyringWire = z.infer<typeof VaultKeyringSchema>;

// Atomic onboarding body: the directory registration (proof of possession) folded
// together with the vault (keyring + sealed items + signed manifest), so both
// commit in one server transaction. Shared so the server route and the UI client
// derive the exact same wire shape from one definition.
export const VaultStoreBodySchema = z.object({
  registration: CompleteKeyPossessionBodySchema,
  keyring: VaultKeyringSchema,
  items: z.array(VaultItemSchema).min(1).max(1024),
  manifest: z.string().min(1).max(MAX_MANIFEST),
  manifest_sig: z.string().min(1).max(MAX_KEY_B64),
});

export type VaultStoreBody = z.infer<typeof VaultStoreBodySchema>;

// PoP-gated fetch: the client presents the challenge it was issued plus a
// signature over it by the vault auth key.
export const VaultFetchBodySchema = z.object({
  challenge_id: z.string().min(1).max(256),
  proof: z.string().min(1).max(MAX_KEY_B64), // base64 Ed25519 over the challenge nonce
});

export type VaultFetchBody = z.infer<typeof VaultFetchBodySchema>;

// A single item write, carrying the last revision the client saw for optimistic
// concurrency. `null` means the client believes the item is new.
export const VaultPutItemBodySchema = z.object({
  item: VaultItemSchema,
  last_known_revision_date_millis: z.number().int().nonnegative().nullable(),
  manifest: z.string().min(1).max(MAX_MANIFEST),
  manifest_sig: z.string().min(1).max(MAX_KEY_B64),
  revision: z.number().int().positive(), // the manifest revision; becomes the account revision
});

export type VaultPutItemBody = z.infer<typeof VaultPutItemBodySchema>;

export const VaultApprovalRequestBodySchema = z.object({
  device_public_key: z.string().min(1).max(MAX_DEVICE_KEY_B64),
});

export const VaultApprovalApproveBodySchema = z.object({
  wrapped_device_bootstrap: z.string().min(1).max(MAX_WRAPPED_VRK_B64),
});
