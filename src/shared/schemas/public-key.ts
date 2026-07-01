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

export const GetPublicKeysQuerySchema = z.object({
  user_ids: z.string(), // comma-separated user identifiers
});

export type GetPublicKeysQuery = z.infer<typeof GetPublicKeysQuerySchema>;

export const GetPublicKeysResponseSchema = z.object({
  keys: z.array(PublicKeySchema),
});

export type GetPublicKeysResponse = z.infer<typeof GetPublicKeysResponseSchema>;
