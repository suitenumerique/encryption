import { z } from 'zod';

import { mnemonicLanguageSchema } from '@encryption/src/shared/schemas/mnemonic-language';
import { VaultKeyringSchema } from '@encryption/src/shared/schemas/vault';
import '@encryption/src/shared/zod-jitless';

// Wire schemas of the recovery council (architecture.md Appendix F) whose types the vault and the
// interface need: the roster chain they verify, the escrow the user's vault
// builds, and what a custodian's or a locked-out user's vault opens. Binary
// values are base64; the server verifies the signatures over them, never opens
// a share.

const B64_SMALL = 1024; // a key, a hash, a signature
const B64_WRAP = 4096; // an X-Wing wrap of a share or a transfer key

const b64 = z.string().min(1).max(B64_SMALL);
const wrap = z.string().min(1).max(B64_WRAP);
const slot = z.number().int().min(1).max(255);

export const COUNCIL_MAX_SLOTS = 12;

export const RosterMemberWireSchema = z.object({
  slot,
  user_id: z.string().uuid(),
  identity_public_key: b64,
  name: z.string().nullable(),
});

export const RosterVersionWireSchema = z.object({
  version: z.number().int().positive(),
  threshold: z.number().int().positive(),
  previous_roster_hash: z.string().max(B64_SMALL), // empty for version 1
  members: z.array(RosterMemberWireSchema).max(COUNCIL_MAX_SLOTS),
  signatures: z.array(z.object({ identity_public_key: b64, signature: b64 })).max(64),
});

export type RosterVersionWire = z.infer<typeof RosterVersionWireSchema>;

// What a user's vault signs and submits to enroll (or to re-enroll, or to re-arm
// after a recovery): a dormant credential, one capsule per custodian of the head
// version, the commitments, and the identity signature over all of it.
export const CouncilEscrowBodySchema = z.object({
  council_id: z.string().min(1).max(64),
  roster_version: z.number().int().positive(),
  threshold: z.number().int().positive(),
  credential: VaultKeyringSchema,
  escrow_created_at_millis: z.number().int().nonnegative(),
  secret_commitment: b64,
  // Pedersen commitments of the split, one 32-byte point per coefficient.
  share_commitments: b64,
  shares: z
    .array(z.object({ slot, wrapped_share: wrap }))
    .min(1)
    .max(COUNCIL_MAX_SLOTS),
  escrow_signature: b64,
});

export type CouncilEscrowBody = z.infer<typeof CouncilEscrowBodySchema>;

// The signed record of an escrow as the server holds it: enough to rebuild the
// signed bytes (src/crypto/council.ts) and check them against the user's identity.
export const CouncilEscrowRecordWireSchema = z.object({
  council_id: z.string(),
  roster_version: z.number().int().positive(),
  roster_hash: b64,
  threshold: z.number().int().positive(),
  escrow_created_at_millis: z.number().int().nonnegative(),
  credential_auth_public_key_hash: b64,
  secret_commitment: b64,
  share_commitments: b64,
  shares: z.array(z.object({ slot, capsule_hash: b64 })),
  escrow_signature: b64,
});

export type CouncilEscrowRecordWire = z.infer<typeof CouncilEscrowRecordWireSchema>;

// A custodian's share of an escrow's current split, as their vault receives it:
// wrapped for them directly, or the sub-shares of a resharing to add up.
export const CouncilCapsuleWireSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('direct'), generation: z.number().int().positive(), slot, wrapped_share: wrap }),
  z.object({
    kind: z.literal('reshared'),
    generation: z.number().int().positive(),
    slot,
    session_id: z.string().uuid(),
    escrow_id: z.string().uuid(),
    target_roster_version: z.number().int().positive(),
    helpers: z.array(
      z.object({
        helper_slot: slot,
        helper_identity_public_key: b64,
        wrapped_transfer_key: wrap,
        binding_signature: b64,
        sealed_sub_share: z.string().min(1).max(B64_SMALL),
        commitments: b64,
        commitments_signature: b64,
      })
    ),
  }),
]);

export type CouncilCapsuleWire = z.infer<typeof CouncilCapsuleWireSchema>;

export const CouncilContributionBodySchema = z.object({
  slot,
  wrapped_share: wrap,
  in_person: z.boolean(),
  signature: b64,
});

export type CouncilContributionBody = z.infer<typeof CouncilContributionBodySchema>;

// The share a custodian handed over at the meeting, as remote custodians' vaults
// receive it: its signed record attests the request's key was checked in person.
export const CouncilAttestationWireSchema = z.object({
  slot,
  custodian_user_id: z.string().uuid(),
  wrapped_share: wrap,
  signature: b64,
});

export type CouncilAttestationWire = z.infer<typeof CouncilAttestationWireSchema>;

// What the locked-out user's vault receives once the request is released.
export const CouncilReleasedSharesSchema = z.object({
  request_id: z.string().uuid(),
  council_id: z.string(),
  user_id: z.string().uuid(),
  generation: z.number().int().positive(),
  threshold: z.number().int().positive(),
  // The commitments of the current split: the signed ones until a resharing,
  // then the sum of its helpers' (same constant term).
  share_commitments: b64,
  // The wordlist the dormant phrase was written in: the phrase string, not only
  // its entropy, derives the credential.
  lang: mnemonicLanguageSchema,
  escrow: CouncilEscrowRecordWireSchema,
  contributions: z.array(
    z.object({
      slot,
      wrapped_share: wrap,
      in_person: z.boolean(),
      signature: b64,
      custodian_user_id: z.string().uuid(),
      custodian_identity_public_key: b64,
      custodian_name: z.string().nullable(),
    })
  ),
});

export type CouncilReleasedShares = z.infer<typeof CouncilReleasedSharesSchema>;

// A resharing batch as a helper's vault receives it, and what it sends back.
export const CouncilReshareBatchSchema = z.object({
  session_id: z.string().uuid(),
  council_id: z.string(),
  helper_slots: z.array(slot),
  my_slot: slot,
  target_roster_version: z.number().int().positive(),
  target_threshold: z.number().int().positive(),
  chain: z.array(RosterVersionWireSchema),
  transfer_keys_done: z.boolean(),
  escrows: z.array(
    z.object({ escrow_id: z.string().uuid(), user_id: z.string().uuid(), record: CouncilEscrowRecordWireSchema, capsule: CouncilCapsuleWireSchema })
  ),
  remaining: z.number().int().nonnegative(),
});

export type CouncilReshareBatch = z.infer<typeof CouncilReshareBatchSchema>;

// A new custodian's reshared shares to check, and what its vault found.
export const CouncilCheckBatchSchema = z.object({
  council_id: z.string(),
  chain: z.array(RosterVersionWireSchema),
  escrows: z.array(
    z.object({ escrow_id: z.string().uuid(), user_id: z.string().uuid(), record: CouncilEscrowRecordWireSchema, capsule: CouncilCapsuleWireSchema })
  ),
  remaining: z.number().int().nonnegative(),
});

export type CouncilCheckBatch = z.infer<typeof CouncilCheckBatchSchema>;

export const CouncilCheckResultsBodySchema = z.object({
  results: z
    .array(z.object({ escrow_id: z.string().uuid(), valid: z.boolean(), faulty_helper_slot: slot.nullable() }))
    .min(1)
    .max(200),
});

export type CouncilCheckResultsBody = z.infer<typeof CouncilCheckResultsBodySchema>;

export const CouncilReshareKeysBodySchema = z.object({
  keys: z
    .array(z.object({ recipient_slot: slot, wrapped_transfer_key: wrap, binding_signature: b64 }))
    .min(1)
    .max(COUNCIL_MAX_SLOTS),
});

export type CouncilReshareKeysBody = z.infer<typeof CouncilReshareKeysBodySchema>;

export const CouncilReshareSubSharesBodySchema = z.object({
  escrows: z
    .array(
      z.object({
        escrow_id: z.string().uuid(),
        commitments: b64,
        commitments_signature: b64,
        sub_shares: z
          .array(z.object({ recipient_slot: slot, sealed: z.string().min(1).max(B64_SMALL) }))
          .min(1)
          .max(COUNCIL_MAX_SLOTS),
      })
    )
    .min(1)
    .max(200),
});

export type CouncilReshareSubSharesBody = z.infer<typeof CouncilReshareSubSharesBodySchema>;
