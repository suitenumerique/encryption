import { z } from 'zod';

// Bodies & responses for the two-phase proof-of-possession flow used at
// `/api/keys/init` and `/api/keys/complete`. See
// src/crypto/key-possession-challenge.ts for the underlying protocol.

export const InitKeyPossessionBodySchema = z.object({
  user_id: z.string().min(1),
  public_key: z.string(), // base64-encoded [version:1][xwingPubkey:1216]
});

export type InitKeyPossessionBody = z.infer<typeof InitKeyPossessionBodySchema>;

export const InitKeyPossessionResponseSchema = z.object({
  challenge_id: z.string().uuid(),
  ciphertext: z.string(), // base64-encoded X-Wing ciphertext (1120 bytes)
});

export type InitKeyPossessionResponse = z.infer<typeof InitKeyPossessionResponseSchema>;

export const CompleteKeyPossessionBodySchema = z.object({
  challenge_id: z.string().uuid(),
  response: z.string(), // base64-encoded HMAC-SHA256 tag (32 bytes)
});

export type CompleteKeyPossessionBody = z.infer<typeof CompleteKeyPossessionBodySchema>;

export const CompleteKeyPossessionResponseSchema = z.object({
  user_id: z.string(),
  public_key: z.string(),
});

export type CompleteKeyPossessionResponse = z.infer<typeof CompleteKeyPossessionResponseSchema>;
