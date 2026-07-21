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
  user_id: z.string().uuid(), // INTERNAL encryption-service user id, never an OIDC sub
  sub: z.string().min(1).optional(), // echoed only for records matched through the `subs=` query form, so the caller can correlate
  encryption_public_key: z.string(), // base64 [version:1][xwingPubkey:1216]
  signature_public_key: z.string(), // base64 [version:1][ed25519Pubkey:32] — the identity
  key_binding_signature: z.string(), // base64 Ed25519 signature over the canonical registration payload
  version: z.number().int().positive(),
  created_at_millis: z.number().int().nonnegative(), // signed creation time (ms since epoch)
});

export type PublicKey = z.infer<typeof PublicKeySchema>;

// The listing endpoint accepts two id spaces:
//  - `user_ids`: canonical INTERNAL ids (uuids, so comma-splitting is unambiguous);
//  - `subs`: OIDC subs, resolved through oidc_accounts server-side — the form a
//    product uses at its "list users to share with" step, since subs are what it
//    holds. Records matched this way echo the sub back for correlation.
// Both forms take REPEATED query parameters (`?subs=a&subs=b`), never a
// comma-joined list. OIDC constrains `sub` to at most 255 ASCII characters and
// excludes no character, so a sub may legitimately contain a comma; the query
// value is percent-decoded before any split, so encoding cannot rescue a
// comma-joined list and one such sub would silently shatter into two bogus
// lookups. Repetition is unambiguous by construction. A single occurrence
// arrives as a bare string and is normalized to a one-element array so callers
// downstream always see a list.
// Both lists feed IN(...) queries, so each is bounded here: at most 100 ids,
// each non-empty and length-capped, so a caller cannot enumerate with (or blow
// up the query on) an unbounded batch. EXACTLY one of the two forms must be
// present: mixing them would make the response keying ambiguous (a record
// matched by both forms can only be echoed one way).
const MAX_USER_IDS = 100;
const MAX_USER_ID_LENGTH = 200;

const asList = z.union([z.string(), z.array(z.string())]).transform((value) => (Array.isArray(value) ? value : [value]));

// Internal ids are uuids by construction; subs are provider-defined free-form.
const userIdList = asList.pipe(z.array(z.string().uuid()).min(1).max(MAX_USER_IDS));

const subList = asList.pipe(z.array(z.string().min(1).max(MAX_USER_ID_LENGTH)).min(1).max(MAX_USER_IDS));

export const GetPublicKeysQuerySchema = z
  .object({
    user_ids: userIdList.optional(),
    subs: subList.optional(),
  })
  .refine((query) => (query.user_ids !== undefined) !== (query.subs !== undefined), {
    message: 'exactly one of user_ids or subs is required',
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
