import { z } from 'zod';

import {
  MSG_VAULT_ACCEPT_FINGERPRINT,
  MSG_VAULT_CHECK_FINGERPRINTS,
  MSG_VAULT_CLAIM_TRANSFER_IMPORT,
  MSG_VAULT_DECRYPT_WITH_KEY,
  MSG_VAULT_DESTROY_KEYS,
  MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY,
  MSG_VAULT_ENCRYPT_WITHOUT_KEY,
  MSG_VAULT_ENCRYPT_WITH_KEY,
  MSG_VAULT_EXPORT_BACKUP,
  MSG_VAULT_GENERATE_KEYS,
  MSG_VAULT_GET_KNOWN_FINGERPRINTS,
  MSG_VAULT_GET_PUBLIC_KEY,
  MSG_VAULT_HAS_KEYS,
  MSG_VAULT_IMPORT_BACKUP,
  MSG_VAULT_PREPARE_TRANSFER_EXPORT,
  MSG_VAULT_READY,
  MSG_VAULT_REFUSE_FINGERPRINT,
  MSG_VAULT_RESPOND_TO_KEY_CHALLENGE,
  MSG_VAULT_RESULT,
  MSG_VAULT_REWRAP_NESTED_KEY,
  MSG_VAULT_SHARE_KEYS,
  MSG_VAULT_WRAP_NESTED_KEY,
} from '@encryption/src/shared/constants';

// ============================================================================
// Operations available to ALL callers (suite products via data.encryption)
// These are safe: they only read keys or encrypt/decrypt content.
// ============================================================================

export const VaultHasKeysRequest = z.object({
  type: z.literal(MSG_VAULT_HAS_KEYS),
  requestId: z.string(),
});

export const VaultGetPublicKeyRequest = z.object({
  type: z.literal(MSG_VAULT_GET_PUBLIC_KEY),
  requestId: z.string(),
});

export const VaultEncryptWithoutKeyRequest = z.object({
  type: z.literal(MSG_VAULT_ENCRYPT_WITHOUT_KEY),
  requestId: z.string(),
  payload: z.object({
    data: z.string(), // base64-encoded content
    userPublicKeys: z.record(z.string(), z.string()), // userId → base64 public key (SPKI)
  }),
});

export const VaultEncryptNestedWithoutKeyRequest = z.object({
  type: z.literal(MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY),
  requestId: z.string(),
  payload: z.object({
    data: z.string(), // base64-encoded content
    encryptedSymmetricKey: z.string(), // caller's entry key (asymmetric bootstrap)
    encryptedKeyChain: z.array(z.string()).optional(), // symmetric wrappings from entry down to parent
  }),
});

export const VaultEncryptWithKeyRequest = z.object({
  type: z.literal(MSG_VAULT_ENCRYPT_WITH_KEY),
  requestId: z.string(),
  payload: z.object({
    data: z.string(), // base64-encoded content to encrypt
    encryptedSymmetricKey: z.string(), // base64-encoded symmetric key encrypted with user's public key
    encryptedKeyChain: z.array(z.string()).optional(), // optional chain of wrapped keys (Drive key hierarchy)
  }),
});

export const VaultDecryptWithKeyRequest = z.object({
  type: z.literal(MSG_VAULT_DECRYPT_WITH_KEY),
  requestId: z.string(),
  payload: z.object({
    encryptedData: z.string(), // base64-encoded
    encryptedSymmetricKey: z.string(), // base64-encoded symmetric key encrypted with user's public key
    encryptedKeyChain: z.array(z.string()).optional(), // optional chain of wrapped keys (Drive key hierarchy)
  }),
});

export const VaultRewrapNestedKeyRequest = z.object({
  type: z.literal(MSG_VAULT_REWRAP_NESTED_KEY),
  requestId: z.string(),
  payload: z.object({
    encryptedSymmetricKey: z.string(), // base64-encoded — user's entry-point key (root key wrapped under their pubkey)
    oldEncryptedKey: z.string(), // base64-encoded — the resource's K_file wrapped under its OLD parent's key
    oldEncryptedKeyChain: z.array(z.string()).optional(), // chain entry → OLD parent (omit when old parent is the root)
    newEncryptedKeyChain: z.array(z.string()).optional(), // chain entry → NEW parent (omit when new parent is the root)
  }),
});

export const VaultWrapNestedKeyRequest = z.object({
  type: z.literal(MSG_VAULT_WRAP_NESTED_KEY),
  requestId: z.string(),
  payload: z.object({
    userEncryptedKey: z.string(), // base64-encoded — K_item wrapped under user's pubkey (per-user wrap from the access row)
    newEntryEncryptedSymmetricKey: z.string(), // base64-encoded — user's entry key for the destination tree
    newEncryptedKeyChain: z.array(z.string()).optional(), // chain entry → NEW parent (omit when new parent is the root)
  }),
});

export const VaultShareKeysRequest = z.object({
  type: z.literal(MSG_VAULT_SHARE_KEYS),
  requestId: z.string(),
  payload: z.object({
    encryptedSymmetricKey: z.string(), // base64-encoded
    userPublicKeys: z.record(z.string(), z.string()), // userId → base64 public key
    encryptedKeyChain: z.array(z.string()).optional(), // optional chain of wrapped keys (Drive key hierarchy)
  }),
});

export const VaultCheckFingerprintsRequest = z.object({
  type: z.literal(MSG_VAULT_CHECK_FINGERPRINTS),
  requestId: z.string(),
  payload: z.object({
    userFingerprints: z.record(z.string(), z.string()), // userId → fingerprint (from product's share-time snapshot)
    currentUserId: z.string().optional(),
  }),
});

export const VaultAcceptFingerprintRequest = z.object({
  type: z.literal(MSG_VAULT_ACCEPT_FINGERPRINT),
  requestId: z.string(),
  payload: z.object({
    userId: z.string(),
    fingerprint: z.string(),
  }),
});

export const VaultRefuseFingerprintRequest = z.object({
  type: z.literal(MSG_VAULT_REFUSE_FINGERPRINT),
  requestId: z.string(),
  payload: z.object({
    userId: z.string(),
    fingerprint: z.string(),
  }),
});

export const VaultGetKnownFingerprintsRequest = z.object({
  type: z.literal(MSG_VAULT_GET_KNOWN_FINGERPRINTS),
  requestId: z.string(),
});

/** Operations any product can call */
export const VaultProductRequestSchema = z.discriminatedUnion('type', [
  VaultHasKeysRequest,
  VaultGetPublicKeyRequest,
  VaultEncryptWithoutKeyRequest,
  VaultEncryptNestedWithoutKeyRequest,
  VaultEncryptWithKeyRequest,
  VaultDecryptWithKeyRequest,
  VaultRewrapNestedKeyRequest,
  VaultWrapNestedKeyRequest,
  VaultShareKeysRequest,
  VaultCheckFingerprintsRequest,
  VaultAcceptFingerprintRequest,
  VaultRefuseFingerprintRequest,
  VaultGetKnownFingerprintsRequest,
]);

// ============================================================================
// Privileged operations - ONLY from encryption
// These are sensitive: they create, export, import, or destroy key material.
// ============================================================================

export const VaultGenerateKeysRequest = z.object({
  type: z.literal(MSG_VAULT_GENERATE_KEYS),
  requestId: z.string(),
});

export const VaultRespondToKeyChallengeRequest = z.object({
  type: z.literal(MSG_VAULT_RESPOND_TO_KEY_CHALLENGE),
  requestId: z.string(),
  payload: z.object({
    challengeId: z.string().uuid(),
    ciphertext: z.string(), // base64 X-Wing ciphertext from /api/keys/init
  }),
});

export const VaultExportBackupRequest = z.object({
  type: z.literal(MSG_VAULT_EXPORT_BACKUP),
  requestId: z.string(),
});

export const VaultImportBackupRequest = z.object({
  type: z.literal(MSG_VAULT_IMPORT_BACKUP),
  requestId: z.string(),
  payload: z.object({
    passphrase: z.string(),
  }),
});

export const VaultDestroyKeysRequest = z.object({
  type: z.literal(MSG_VAULT_DESTROY_KEYS),
  requestId: z.string(),
});

export const VaultPrepareTransferExportRequest = z.object({
  type: z.literal(MSG_VAULT_PREPARE_TRANSFER_EXPORT),
  requestId: z.string(),
  payload: z
    .object({
      language: z.enum(['french', 'english']).optional(),
    })
    .optional(),
});

export const VaultClaimTransferImportRequest = z.object({
  type: z.literal(MSG_VAULT_CLAIM_TRANSFER_IMPORT),
  requestId: z.string(),
  payload: z.object({
    encryptedPayload: z.string(), // base64 encrypted payload from the server
    transferPassphrase: z.string(), // 24-word mnemonic passphrase representing the AES key
  }),
});

/** Privileged operations only encryption can call */
export const VaultPrivilegedRequestSchema = z.discriminatedUnion('type', [
  VaultGenerateKeysRequest,
  VaultRespondToKeyChallengeRequest,
  VaultExportBackupRequest,
  VaultImportBackupRequest,
  VaultDestroyKeysRequest,
  VaultPrepareTransferExportRequest,
  VaultClaimTransferImportRequest,
]);

// ============================================================================
// Combined schema (all operations) and types
// ============================================================================

export const VaultRequestSchema = z.discriminatedUnion('type', [
  // Product operations
  VaultHasKeysRequest,
  VaultGetPublicKeyRequest,
  VaultEncryptWithoutKeyRequest,
  VaultEncryptNestedWithoutKeyRequest,
  VaultEncryptWithKeyRequest,
  VaultDecryptWithKeyRequest,
  VaultRewrapNestedKeyRequest,
  VaultWrapNestedKeyRequest,
  VaultShareKeysRequest,
  VaultCheckFingerprintsRequest,
  VaultAcceptFingerprintRequest,
  VaultRefuseFingerprintRequest,
  VaultGetKnownFingerprintsRequest,
  // Privileged operations
  VaultGenerateKeysRequest,
  VaultRespondToKeyChallengeRequest,
  VaultExportBackupRequest,
  VaultImportBackupRequest,
  VaultDestroyKeysRequest,
  VaultPrepareTransferExportRequest,
  VaultClaimTransferImportRequest,
]);

export type VaultRequest = z.infer<typeof VaultRequestSchema>;

/** Set of operation types that require encryption origin */
export const PRIVILEGED_OPERATIONS = new Set<string>([
  MSG_VAULT_GENERATE_KEYS,
  MSG_VAULT_RESPOND_TO_KEY_CHALLENGE,
  MSG_VAULT_EXPORT_BACKUP,
  MSG_VAULT_IMPORT_BACKUP,
  MSG_VAULT_DESTROY_KEYS,
  MSG_VAULT_PREPARE_TRANSFER_EXPORT,
  MSG_VAULT_CLAIM_TRANSFER_IMPORT,
]);

// ============================================================================
// Response types (vault -> parent)
// ============================================================================

export const VaultReadyResponse = z.object({
  type: z.literal(MSG_VAULT_READY),
});

export const VaultSuccessResponse = z.object({
  type: z.literal(MSG_VAULT_RESULT),
  requestId: z.string(),
  success: z.literal(true),
  data: z.unknown(),
});

export const VaultErrorResponse = z.object({
  type: z.literal(MSG_VAULT_RESULT),
  requestId: z.string(),
  success: z.literal(false),
  error: z.string(),
  code: z.string().optional(),
});

export type VaultResponse = z.infer<typeof VaultReadyResponse> | z.infer<typeof VaultSuccessResponse> | z.infer<typeof VaultErrorResponse>;
