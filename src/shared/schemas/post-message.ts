import { z } from 'zod';

import {
  MSG_VAULT_ACCEPT_FINGERPRINT,
  MSG_VAULT_APPROVE_DEVICE,
  MSG_VAULT_BUILD_EMERGENCY_REARMS,
  MSG_VAULT_CHANGE_RECOVERY_PHRASE,
  MSG_VAULT_CHECK_FINGERPRINTS,
  MSG_VAULT_COMMIT_STAGED,
  MSG_VAULT_COMPLETE_DEVICE_APPROVAL,
  MSG_VAULT_COUNCIL_CHECK_ESCROW,
  MSG_VAULT_COUNCIL_CHECK_SHARES,
  MSG_VAULT_COUNCIL_COMPLETE_RECOVERY,
  MSG_VAULT_COUNCIL_CONTRIBUTE,
  MSG_VAULT_COUNCIL_CREATE_ESCROW,
  MSG_VAULT_COUNCIL_DISCARD_RECOVERY,
  MSG_VAULT_COUNCIL_MARK_VERIFIED,
  MSG_VAULT_COUNCIL_REACTIVATE,
  MSG_VAULT_COUNCIL_REQUEST_KEY,
  MSG_VAULT_COUNCIL_RESHARE_BATCH,
  MSG_VAULT_COUNCIL_SIGN_ROSTER,
  MSG_VAULT_COUNCIL_START_REQUEST,
  MSG_VAULT_COUNCIL_VERIFY_ROSTER,
  MSG_VAULT_CREATE_EMERGENCY_ESCROW,
  MSG_VAULT_DECRYPT_WITH_KEY,
  MSG_VAULT_DESTROY_KEYS,
  MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY,
  MSG_VAULT_ENCRYPT_WITHOUT_KEY,
  MSG_VAULT_ENCRYPT_WITH_KEY,
  MSG_VAULT_FETCH_PUBLIC_KEYS,
  MSG_VAULT_GENERATE_KEYS,
  MSG_VAULT_GET_KNOWN_FINGERPRINTS,
  MSG_VAULT_GET_PUBLIC_KEY,
  MSG_VAULT_HAS_KEYS,
  MSG_VAULT_PREPARE_ONBOARDING,
  MSG_VAULT_REACTIVATE,
  MSG_VAULT_REACTIVATE_WITH_KEYRING,
  MSG_VAULT_READY,
  MSG_VAULT_REFUSE_FINGERPRINT,
  MSG_VAULT_RESOLVE_USER,
  MSG_VAULT_RESPOND_TO_KEY_CHALLENGE,
  MSG_VAULT_RESTORE_FROM_PHRASE,
  MSG_VAULT_RESULT,
  MSG_VAULT_REVEAL_EMERGENCY_PHRASE,
  MSG_VAULT_REWRAP_NESTED_KEY,
  MSG_VAULT_SHARE_KEYS,
  MSG_VAULT_SIGN_KEY_REGISTRATION,
  MSG_VAULT_SIGN_REQUEST,
  MSG_VAULT_START_DEVICE_APPROVAL,
  MSG_VAULT_SYNC,
  MSG_VAULT_UNCOMMIT_STAGED,
  MSG_VAULT_VERIFY_ESCROWS,
  MSG_VAULT_WRAP_NESTED_KEY,
} from '@encryption/src/shared/constants';
import { EmergencyEscrowRecordSchema } from '@encryption/src/shared/schemas/emergency-access';
import { mnemonicLanguageSchema } from '@encryption/src/shared/schemas/mnemonic-language';
import '@encryption/src/shared/zod-jitless';

// ============================================================================
// Requests (parent -> vault): one payload schema per operation
// ============================================================================

// Every message is parsed against its operation's schema before anything runs: an
// allowed product can send anything, and a malformed call must fail as one, never
// read as an empty list or reach libsodium. Binary fields are checked by type only
// (no copy, no scan), so a large file costs nothing.
const binary = z
  .union([z.instanceof(ArrayBuffer), z.instanceof(Uint8Array)])
  .transform((value): ArrayBuffer => (value instanceof ArrayBuffer ? value : (value.slice().buffer as ArrayBuffer)));
const binaryChain = z.array(binary).max(64);
const id = z.string().min(1).max(256);
const ids = z.array(id).max(1000);
const fingerprint = z.string().min(1).max(256);
const idToken = z.string().min(1).max(16_384);
const lang = mnemonicLanguageSchema.optional();
const waitTimeDays = z.number().int().nonnegative();
const empty = z.object({});

// A trust decision names its target EITHER by internal user id (the flows whose
// directory lookups already yield internal ids) OR by sub (the verify/profile
// screens), never neither.
const fingerprintTarget = z.union([z.object({ userId: id, fingerprint }), z.object({ sub: id, fingerprint })]);

// Council messages: the interface's own fields are checked here; what came from the
// server inside them (chains, records, capsules, batches) is parsed where it is used,
// so a malformed one fails as VAULT_INTEGRITY_FAILED rather than as a bad request.
const councilId = z.string().min(1).max(64);
const fromServer = z.unknown();
const chain = z.array(fromServer).max(1000);

export const VAULT_REQUEST_PAYLOADS = {
  // Product operations (any allowed origin)
  [MSG_VAULT_HAS_KEYS]: empty,
  [MSG_VAULT_GET_PUBLIC_KEY]: empty,
  [MSG_VAULT_ENCRYPT_WITHOUT_KEY]: z.object({ data: binary, recipientSubs: ids }),
  [MSG_VAULT_ENCRYPT_NESTED_WITHOUT_KEY]: z.object({ data: binary, encryptedSymmetricKey: binary, encryptedKeyChain: binaryChain.optional() }),
  [MSG_VAULT_ENCRYPT_WITH_KEY]: z.object({ data: binary, encryptedSymmetricKey: binary, encryptedKeyChain: binaryChain.optional() }),
  [MSG_VAULT_DECRYPT_WITH_KEY]: z.object({
    encryptedData: binary,
    encryptedSymmetricKey: binary,
    encryptedKeyChain: binaryChain.optional(),
    keyVersion: z.number().int().nonnegative(),
  }),
  [MSG_VAULT_REWRAP_NESTED_KEY]: z.object({
    encryptedSymmetricKey: binary,
    oldEncryptedKey: binary,
    oldEncryptedKeyChain: binaryChain.optional(),
    newEncryptedKeyChain: binaryChain.optional(),
  }),
  [MSG_VAULT_WRAP_NESTED_KEY]: z.object({
    userEncryptedKey: binary,
    newEntryEncryptedSymmetricKey: binary,
    newEncryptedKeyChain: binaryChain.optional(),
  }),
  [MSG_VAULT_SHARE_KEYS]: z.object({
    encryptedSymmetricKey: binary,
    recipientSubs: ids,
    encryptedKeyChain: binaryChain.optional(),
    ownerSub: id.optional(),
  }),
  [MSG_VAULT_FETCH_PUBLIC_KEYS]: z.object({ userIds: ids.optional(), subs: ids.optional() }),
  [MSG_VAULT_CHECK_FINGERPRINTS]: z.object({ userFingerprints: z.record(id, fingerprint) }),
  [MSG_VAULT_GET_KNOWN_FINGERPRINTS]: empty,

  // Privileged operations (the interface only, see PRIVILEGED_OPERATIONS)
  [MSG_VAULT_RESOLVE_USER]: empty,
  [MSG_VAULT_ACCEPT_FINGERPRINT]: fingerprintTarget,
  [MSG_VAULT_REFUSE_FINGERPRINT]: fingerprintTarget,
  [MSG_VAULT_GENERATE_KEYS]: empty,
  [MSG_VAULT_SIGN_KEY_REGISTRATION]: z.object({ version: z.number().int().positive(), createdAtMillis: z.number().int().nonnegative() }),
  [MSG_VAULT_RESPOND_TO_KEY_CHALLENGE]: z.object({ challengeId: id, ciphertext: z.string().min(1).max(16_384) }),
  [MSG_VAULT_DESTROY_KEYS]: empty,
  [MSG_VAULT_COMMIT_STAGED]: empty,
  [MSG_VAULT_UNCOMMIT_STAGED]: empty,
  [MSG_VAULT_PREPARE_ONBOARDING]: z.object({
    lang,
    version: z.number().int().nonnegative().optional(),
    generation: z.number().int().nonnegative().optional(),
    reusePhrase: z.string().max(1024).optional(),
  }),
  [MSG_VAULT_CHANGE_RECOVERY_PHRASE]: z.object({ lang }),
  [MSG_VAULT_RESTORE_FROM_PHRASE]: z.object({ recoveryPhrase: z.string().max(1024), idToken }),
  [MSG_VAULT_REACTIVATE]: z.object({ recoveryPhrase: z.string().max(1024), idToken, handedOver: z.boolean().optional() }),
  [MSG_VAULT_REACTIVATE_WITH_KEYRING]: z.object({ idToken, keyring: z.record(z.string(), z.unknown()) }),
  [MSG_VAULT_SYNC]: z.object({ idToken: idToken.nullish() }),
  [MSG_VAULT_SIGN_REQUEST]: z.object({ method: z.string().min(1).max(16), path: z.string().min(1).max(2048), body: z.string().optional() }),
  [MSG_VAULT_START_DEVICE_APPROVAL]: empty,
  [MSG_VAULT_COMPLETE_DEVICE_APPROVAL]: z.object({ wrappedDeviceBootstrap: z.string().min(1).max(65_536), idToken: idToken.nullish() }),
  [MSG_VAULT_APPROVE_DEVICE]: z.object({ devicePublicKey: z.string().min(1).max(8192), expectedDecimal: z.string().min(1).max(64) }),
  [MSG_VAULT_CREATE_EMERGENCY_ESCROW]: z.object({ granteeUserId: id, waitTimeDays, lang }),
  [MSG_VAULT_BUILD_EMERGENCY_REARMS]: z.object({
    rearms: z.array(z.object({ emergencyAccessId: id, granteeUserId: id, waitTimeDays })).max(1000),
    lang,
  }),
  [MSG_VAULT_VERIFY_ESCROWS]: z.object({
    contacts: z.array(z.object({ id, grantee_user_id: id, wait_time_days: waitTimeDays, escrow: EmergencyEscrowRecordSchema })).max(1000),
  }),
  [MSG_VAULT_REVEAL_EMERGENCY_PHRASE]: z.object({
    grantorUserId: id,
    lang: mnemonicLanguageSchema,
    waitTimeDays,
    escrow: EmergencyEscrowRecordSchema,
  }),
  [MSG_VAULT_COUNCIL_VERIFY_ROSTER]: z.object({ councilId, chain, escrow: fromServer.optional() }),
  [MSG_VAULT_COUNCIL_MARK_VERIFIED]: z.object({ councilId, chain }),
  [MSG_VAULT_COUNCIL_CREATE_ESCROW]: z.object({ councilId, chain, escrow: fromServer.optional(), lang }),
  [MSG_VAULT_COUNCIL_CHECK_ESCROW]: z.object({ record: fromServer, chain }),
  [MSG_VAULT_COUNCIL_START_REQUEST]: empty,
  [MSG_VAULT_COUNCIL_REQUEST_KEY]: z.object({ serverFingerprint: z.string().max(64).nullish() }),
  [MSG_VAULT_COUNCIL_COMPLETE_RECOVERY]: z.object({ released: fromServer, idToken }),
  [MSG_VAULT_COUNCIL_REACTIVATE]: z.object({ idToken }),
  [MSG_VAULT_COUNCIL_DISCARD_RECOVERY]: empty,
  [MSG_VAULT_COUNCIL_CONTRIBUTE]: z.object({ detail: fromServer, inPerson: z.boolean(), meetingCode: z.string().max(128).optional() }),
  [MSG_VAULT_COUNCIL_SIGN_ROSTER]: z.object({ councilId, chain, proposal: fromServer }),
  [MSG_VAULT_COUNCIL_RESHARE_BATCH]: z.object({ batch: fromServer }),
  [MSG_VAULT_COUNCIL_CHECK_SHARES]: z.object({ batch: fromServer }),
} satisfies Record<string, z.ZodType>;

type VaultRequestPayloads = { [K in keyof typeof VAULT_REQUEST_PAYLOADS]: z.output<(typeof VAULT_REQUEST_PAYLOADS)[K]> };

/** A request whose payload passed its operation's schema; `switch (request.type)` narrows the payload. */
export type VaultRequest = { [K in keyof VaultRequestPayloads]: { type: K; payload: VaultRequestPayloads[K] } }[keyof VaultRequestPayloads];

/**
 * The request, or why it is refused: an unknown operation, or the paths of the
 * fields that do not match (never their values, which may be secrets).
 */
export function parseVaultRequest(type: unknown, payload: unknown): { request: VaultRequest } | { error: string } {
  if (typeof type !== 'string' || !Object.hasOwn(VAULT_REQUEST_PAYLOADS, type)) return { error: 'Unknown operation.' };

  const result = VAULT_REQUEST_PAYLOADS[type as keyof typeof VAULT_REQUEST_PAYLOADS].safeParse(payload ?? {});

  if (!result.success) {
    const fields = [...new Set(result.error.issues.map((issue) => issue.path.join('.') || '(payload)'))];

    return { error: `Malformed "${type}" request: ${fields.join(', ')}.` };
  }

  return { request: { type, payload: result.data } as VaultRequest };
}

/** Set of operation types that require encryption origin */
export const PRIVILEGED_OPERATIONS = new Set<string>([
  MSG_VAULT_RESOLVE_USER,
  MSG_VAULT_GENERATE_KEYS,
  MSG_VAULT_SIGN_KEY_REGISTRATION,
  MSG_VAULT_RESPOND_TO_KEY_CHALLENGE,
  MSG_VAULT_DESTROY_KEYS,
  MSG_VAULT_COMMIT_STAGED,
  MSG_VAULT_UNCOMMIT_STAGED,
  MSG_VAULT_PREPARE_ONBOARDING,
  MSG_VAULT_CHANGE_RECOVERY_PHRASE,
  MSG_VAULT_RESTORE_FROM_PHRASE,
  MSG_VAULT_REACTIVATE,
  MSG_VAULT_REACTIVATE_WITH_KEYRING,
  MSG_VAULT_SYNC,
  MSG_VAULT_SIGN_REQUEST,
  MSG_VAULT_START_DEVICE_APPROVAL,
  MSG_VAULT_COMPLETE_DEVICE_APPROVAL,
  MSG_VAULT_APPROVE_DEVICE,
  MSG_VAULT_ACCEPT_FINGERPRINT,
  MSG_VAULT_REFUSE_FINGERPRINT,
  MSG_VAULT_CREATE_EMERGENCY_ESCROW,
  MSG_VAULT_BUILD_EMERGENCY_REARMS,
  MSG_VAULT_VERIFY_ESCROWS,
  MSG_VAULT_REVEAL_EMERGENCY_PHRASE,
  MSG_VAULT_COUNCIL_VERIFY_ROSTER,
  MSG_VAULT_COUNCIL_CREATE_ESCROW,
  MSG_VAULT_COUNCIL_CHECK_ESCROW,
  MSG_VAULT_COUNCIL_START_REQUEST,
  MSG_VAULT_COUNCIL_REQUEST_KEY,
  MSG_VAULT_COUNCIL_COMPLETE_RECOVERY,
  MSG_VAULT_COUNCIL_REACTIVATE,
  MSG_VAULT_COUNCIL_DISCARD_RECOVERY,
  MSG_VAULT_COUNCIL_CONTRIBUTE,
  MSG_VAULT_COUNCIL_SIGN_ROSTER,
  MSG_VAULT_COUNCIL_RESHARE_BATCH,
  MSG_VAULT_COUNCIL_CHECK_SHARES,
  MSG_VAULT_COUNCIL_MARK_VERIFIED,
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
