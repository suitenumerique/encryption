import { z } from 'zod';

// Public-key directory schemas. The encoding scheme of `public_key` is
// embedded as a leading version byte inside the blob itself (see
// CRYPTO_VERSION in src/shared/constants.ts), so there is no algorithm
// field on the wire. Registration goes through the proof-of-possession
// flow at `/api/keys/init` + `/api/keys/complete` rather than a single
// PUT — schemas for that live in `./key-possession.ts`.

export const PublicKeySchema = z.object({
  user_id: z.string().min(1),
  public_key: z.string(), // base64-encoded [version:1][xwingPublicKey:1216]
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
