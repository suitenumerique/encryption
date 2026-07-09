import { z } from 'zod';

// Public-key directory schemas. Each registered identity exposes BOTH public
// keys plus the binding signature and the signed metadata, so that any
// consumer can independently verify the record before trusting it (see
// src/crypto/key-registration.ts). The encoding scheme of each key blob is a
// leading version byte (CRYPTO_VERSION in src/shared/constants.ts), so there
// is no separate algorithm field. Registration goes through the
// proof-of-possession flow at `/api/public-keys/register/{init,complete}`;
// schemas for that live in `./key-possession.ts`.

export const PublicKeySchema = z.object({
  user_id: z.string().min(1),
  encryption_public_key: z.string(), // base64 [version:1][xwingPubkey:1216]
  signature_public_key: z.string(), // base64 [version:1][ed25519Pubkey:32] — the identity
  key_binding_signature: z.string(), // base64 Ed25519 signature over the canonical registration payload
  version: z.number().int().positive(),
  created_at_millis: z.number().int().nonnegative(), // signed creation time (ms since epoch)
});

export type PublicKey = z.infer<typeof PublicKeySchema>;

// The listing endpoint feeds `user_ids` straight into an IN(...) query, so the
// list is split, trimmed, and bounded here: at most 100 ids, each non-empty and
// length-capped, so a caller cannot enumerate with (or blow up the query on) an
// unbounded batch. `user_ids` resolves to the parsed array, not the raw string.
const MAX_USER_IDS = 100;
const MAX_USER_ID_LENGTH = 200;

export const GetPublicKeysQuerySchema = z.object({
  user_ids: z
    .string()
    .transform((value) => value.split(',').map((id) => id.trim()))
    .pipe(z.array(z.string().min(1).max(MAX_USER_ID_LENGTH)).min(1).max(MAX_USER_IDS)),
});

export type GetPublicKeysQuery = z.infer<typeof GetPublicKeysQuerySchema>;

export const GetPublicKeysResponseSchema = z.object({
  keys: z.array(PublicKeySchema),
});

export type GetPublicKeysResponse = z.infer<typeof GetPublicKeysResponseSchema>;

// Identity-continuity chain for a single user, walked from the CURRENT identity
// (head) back toward older ones, one link per rotation. Each link is a genuine
// rotation cross-signed by the previous identity key, so a consumer can verify
// the whole chain locally and a compromised registry can only withhold links
// (fail-safe), never fabricate trust.
export const ContinuityLinkSchema = z.object({
  signature_public_key: z.string(), // this identity's key (base64 wire blob)
  previous_signature_public_key: z.string(), // the key that endorsed it
  generation: z.number().int().positive(),
  algo: z.string(),
  continuity_signature: z.string(), // base64 Sign(previousIdentitySecret, this identity)
});

export type ContinuityLinkWire = z.infer<typeof ContinuityLinkSchema>;

export const GetContinuityResponseSchema = z.object({
  chain: z.array(ContinuityLinkSchema),
});

export type GetContinuityResponse = z.infer<typeof GetContinuityResponseSchema>;
