import { z } from 'zod';

import { VaultKeyringSchema } from '@encryption/src/shared/schemas/vault';

// Wire schemas for emergency access (trusted contacts). The escrow blobs are
// opaque base64 the server verifies signatures over but never decodes; sizes
// mirror the bounds used in schemas/vault.ts.

const MAX_KEY_B64 = 1024; // Ed25519 key / signature blob
const MAX_CAPSULE_B64 = 4096; // wrapped emergency-phrase entropy (KEM ct + secretbox)

export const EmergencyAccessStatusSchema = z.enum(['invited', 'confirmed', 'recoveryRequested', 'recoveryApproved']);

export type EmergencyAccessStatusWire = z.infer<typeof EmergencyAccessStatusSchema>;

// The escrow half of a designation / re-arm: everything covered by the
// grantor-identity binding signature (see src/crypto/emergency-escrow.ts),
// minus the credential itself which travels alongside as a VaultKeyringSchema.
export const EmergencyEscrowFieldsSchema = z.object({
  grantee_identity_public_key: z.string().min(1).max(MAX_KEY_B64), // base64 wire blob, pinned at designation
  grantee_key_version: z.number().int().positive(), // encryption-key version the capsule targets
  wrapped_phrase_for_grantee: z.string().min(1).max(MAX_CAPSULE_B64),
  escrow_signature: z.string().min(1).max(MAX_KEY_B64),
  escrow_created_at_millis: z.number().int().nonnegative(),
});

export type EmergencyEscrowFieldsWire = z.infer<typeof EmergencyEscrowFieldsSchema>;

// One-step designation: the escrow (dormant credential + capsule + signature)
// is built client-side and committed with the invitation itself.
export const EmergencyDesignateBodySchema = z.object({
  grantee_user_id: z.string().uuid(),
  wait_time_days: z.number().int().min(1).max(90),
  credential: VaultKeyringSchema,
  ...EmergencyEscrowFieldsSchema.shape,
});

export type EmergencyDesignateBody = z.infer<typeof EmergencyDesignateBodySchema>;

// Replace the escrow material of an existing relationship in place (fresh
// phrase + credential + capsule). Used when the contact rotated their
// encryption key, and as part of the post-recovery burn.
export const EmergencyRearmBodySchema = z.object({
  credential: VaultKeyringSchema,
  ...EmergencyEscrowFieldsSchema.shape,
});

export type EmergencyRearmBody = z.infer<typeof EmergencyRearmBodySchema>;

// Change the wait time: the wait is inside the binding signature, so the
// grantor re-signs over the EXISTING credential + capsule with the new value.
export const EmergencyUpdateBodySchema = z.object({
  wait_time_days: z.number().int().min(1).max(90),
  escrow_signature: z.string().min(1).max(MAX_KEY_B64),
  escrow_created_at_millis: z.number().int().nonnegative(),
});

export type EmergencyUpdateBody = z.infer<typeof EmergencyUpdateBodySchema>;

// A burn + re-arm entry carried by the primary-credential rewrite when a
// recovery is granted: names the relationship and provides its replacement
// escrow. The server rejects the rewrite unless every granted relationship is
// covered (the revealed phrase must not survive the rotation).
export const EmergencyRearmEntrySchema = z.object({
  emergency_access_id: z.string().uuid(),
  ...EmergencyRearmBodySchema.shape,
});

export type EmergencyRearmEntry = z.infer<typeof EmergencyRearmEntrySchema>;

// PUT /api/vault/keyring body: the flat primary credential (unchanged wire for
// a plain phrase change) plus the burn + re-arm entries when required.
export const VaultKeyringUpdateBodySchema = z.object({
  ...VaultKeyringSchema.shape,
  emergency_rearms: z.array(EmergencyRearmEntrySchema).max(64).optional(),
});

export type VaultKeyringUpdateBody = z.infer<typeof VaultKeyringUpdateBodySchema>;

// ---------------------------------------------------------------------------
// Response shapes (server -> interface). Shared so the UI consumes the exact
// same types the routes produce.
// ---------------------------------------------------------------------------

export const EmergencyEscrowRecordSchema = z.object({
  ...EmergencyEscrowFieldsSchema.shape,
  // SHA-256 of the emergency credential's auth verifier, base64. Inside the
  // binding signature; the verifier itself is never returned to any client.
  credential_auth_public_key_hash: z.string().min(1).max(MAX_KEY_B64),
});

export type EmergencyEscrowRecordWire = z.infer<typeof EmergencyEscrowRecordSchema>;

export const EmergencyTrustedEntrySchema = z.object({
  id: z.string().uuid(),
  grantee_user_id: z.string().uuid(),
  grantee_email: z.string(),
  status: EmergencyAccessStatusSchema,
  wait_time_days: z.number().int(),
  created_at_millis: z.number().int(),
  recovery_requested_at_millis: z.number().int().nullable(),
  deadline_millis: z.number().int().nullable(),
  // False once the escrow's vault was superseded by a start-over: still
  // exercisable against that dormant vault (it would resurrect it), but shown
  // apart and excluded from the identity audit (a new vault = new identity).
  vault_active: z.boolean(),
  escrow: EmergencyEscrowRecordSchema,
});

export type EmergencyTrustedEntry = z.infer<typeof EmergencyTrustedEntrySchema>;

export const EmergencyGrantedEntrySchema = z.object({
  id: z.string().uuid(),
  grantor_user_id: z.string().uuid(),
  grantor_email: z.string(),
  status: EmergencyAccessStatusSchema,
  wait_time_days: z.number().int(),
  created_at_millis: z.number().int(),
  recovery_requested_at_millis: z.number().int().nullable(),
  deadline_millis: z.number().int().nullable(),
});

export type EmergencyGrantedEntry = z.infer<typeof EmergencyGrantedEntrySchema>;

export const EmergencyRecoverResponseSchema = z.object({
  id: z.string().uuid(),
  grantor_user_id: z.string().uuid(),
  wait_time_days: z.number().int(),
  lang: z.string(),
  escrow: EmergencyEscrowRecordSchema,
});

export type EmergencyRecoverResponse = z.infer<typeof EmergencyRecoverResponseSchema>;

export const EmergencySearchResponseSchema = z.object({
  user: z.object({ user_id: z.string().uuid(), email: z.string() }).nullable(),
  onboarded: z.boolean(),
});

export type EmergencySearchResponse = z.infer<typeof EmergencySearchResponseSchema>;
