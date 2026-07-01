import { z } from 'zod';

// Bodies & responses for the two-phase proof-of-possession flow used at
// `/api/public-keys/register/init` and `/api/public-keys/register/complete`.
// See src/crypto/key-possession-challenge.ts (encryption-key PoP) and
// src/crypto/key-registration.ts (identity binding + signature-key PoP).

export const InitKeyPossessionBodySchema = z.object({
  user_id: z.string().min(1),
  encryption_public_key: z.string(), // base64 [version:1][xwingPubkey:1216]
  signature_public_key: z.string(), // base64 [version:1][ed25519Pubkey:32] — the identity
  version: z.number().int().positive(), // monotonic per-user key version (>= 1)
  created_at_millis: z.number().int().nonnegative(), // client-asserted creation time, covered by the binding signature
  key_binding_signature: z.string(), // base64 Ed25519 signature over the canonical registration payload
});

export type InitKeyPossessionBody = z.infer<typeof InitKeyPossessionBodySchema>;

export const InitKeyPossessionResponseSchema = z.object({
  challenge_id: z.string().uuid(),
  ciphertext: z.string(), // base64-encoded X-Wing ciphertext (1120 bytes)
});

export type InitKeyPossessionResponse = z.infer<typeof InitKeyPossessionResponseSchema>;

export const CompleteKeyPossessionBodySchema = z.object({
  challenge_id: z.string().uuid(),
  response: z.string(), // base64-encoded HMAC-SHA256 tag (32 bytes) — encryption-key PoP
  challenge_signature: z.string(), // base64-encoded Ed25519 signature over the challenge id — signature-key PoP
});

export type CompleteKeyPossessionBody = z.infer<typeof CompleteKeyPossessionBodySchema>;

export const CompleteKeyPossessionResponseSchema = z.object({
  user_id: z.string(),
  encryption_public_key: z.string(),
  signature_public_key: z.string(),
  key_binding_signature: z.string(),
  version: z.number().int().positive(),
  created_at_millis: z.number().int().nonnegative(),
});

export type CompleteKeyPossessionResponse = z.infer<typeof CompleteKeyPossessionResponseSchema>;
