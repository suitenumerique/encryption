import type { EmergencyDesignateBody } from '@encryption/src/shared/schemas/emergency-access';
import type { CouncilEscrowBody, CouncilEscrowRecordWire, RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import type { VaultItemWire, VaultKeyringWire } from '@encryption/src/shared/schemas/vault';
import type { GetApiPublicKeysResponses } from '@encryption/src/ui/api/generated/types.gen';

const DEMO_USER_ID = '00000000-0000-0000-0000-000000000000';

/** 128-bit identity fingerprint as 40 decimal digits (the verified-out-of-band value). */
export const sampleFingerprint = '1031712345678901234567890123456789012345';

export const samplePublicKey: GetApiPublicKeysResponses[200]['keys'][number] = {
  user_id: DEMO_USER_ID,
  encryption_public_key: fakeBase64(1217), // [version:1][xwingPubkey:1216]
  signature_public_key: fakeBase64(33), // [version:1][ed25519Pubkey:32]
  key_binding_signature: fakeBase64(64), // Ed25519 signature
  version: 1,
  created_at_millis: 1_700_000_000_000,
};

// 24 BIP-39 French words. Structurally shaped like a real Recovery Kit phrase
// so the word-box UI lays out correctly; it derives nothing.
export const sampleRecoveryPhrase =
  'abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger ' +
  'abrupt absence absolu absurde abusif abyssal acacia academie acajou accabler accepter acclamer';

export const sampleVaultKeyring: VaultKeyringWire = {
  wrapped_vrk: fakeBase64(80),
  auth_public_key: fakeBase64(32),
  auth_pub_sig: fakeBase64(64),
  kdf_ops: 3,
  kdf_mem: 67_108_864,
  lang: 'french',
};

const sampleVaultItems: VaultItemWire[] = [
  { item_id: 'identity', type: 'identity', ciphertext: fakeBase64(128), revision_date_millis: 1_700_000_000_000 },
  { item_id: 'enc:1', type: 'encryptionKey', ciphertext: fakeBase64(2048), revision_date_millis: 1_700_000_000_000 },
];

export const sampleOnboardingBundle = {
  recoveryPhrase: sampleRecoveryPhrase,
  keyring: sampleVaultKeyring,
  items: sampleVaultItems,
  manifest: JSON.stringify({ revision: 1, items: sampleVaultItems.map(({ item_id, revision_date_millis }) => ({ item_id, revision_date_millis })) }),
  manifestSig: fakeBase64(64),
};

function fakeBase64(byteLength: number): string {
  const remainder = byteLength % 3;
  const padding = remainder === 0 ? 0 : 3 - remainder;
  const totalChars = Math.ceil(byteLength / 3) * 4;

  return 'A'.repeat(totalChars - padding) + '='.repeat(padding);
}

// A grantor-signed designation body: the dormant emergency credential plus the
// wrapped phrase and binding signature the vault produces for a trusted contact.
export const sampleEmergencyDesignateBody: EmergencyDesignateBody = {
  grantee_user_id: '11111111-1111-1111-1111-111111111111',
  wait_time_days: 15,
  credential: sampleVaultKeyring,
  grantee_identity_public_key: fakeBase64(33),
  grantee_key_version: 1,
  wrapped_phrase_for_grantee: fakeBase64(256),
  escrow_signature: fakeBase64(64),
  escrow_created_at_millis: 1_700_000_000_000,
};

// The escrow record the server returns for a designated contact (the signed
// fields plus the credential auth-key hash the client audits).
export const sampleEmergencyEscrowRecord = {
  grantee_identity_public_key: fakeBase64(33),
  grantee_key_version: 1,
  wrapped_phrase_for_grantee: fakeBase64(256),
  escrow_signature: fakeBase64(64),
  escrow_created_at_millis: 1_700_000_000_000,
  credential_auth_public_key_hash: fakeBase64(32),
};

// ----- Recovery council ---------------------------------------------------------

/** A council's 40-digit code, as its organization publishes it. */
export const sampleCouncilFingerprint = '1284091733520481176234905126639870015423';

export const sampleCouncilMembers = [
  { slot: 1, user_id: '0b7e5f0c-6a0e-4a0f-9d5e-2f1c8e3a9b11', identity_public_key: fakeBase64(33), name: 'Alice Martin' },
  { slot: 2, user_id: '6f2d4c1a-3b5e-4e7f-8a9b-0c1d2e3f4a5b', identity_public_key: fakeBase64(33), name: 'Bruno Petit' },
  { slot: 3, user_id: '9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d', identity_public_key: fakeBase64(33), name: 'Chloé Durand' },
  { slot: 4, user_id: '1e2f3a4b-5c6d-4e7f-8a9b-0c1d2e3f4a5c', identity_public_key: fakeBase64(33), name: 'David Moreau' },
];

export function sampleRosterVersion(overrides: Partial<RosterVersionWire> = {}): RosterVersionWire {
  return {
    version: 1,
    threshold: 2,
    previous_roster_hash: '',
    members: sampleCouncilMembers,
    signatures: sampleCouncilMembers.map(() => ({ identity_public_key: fakeBase64(33), signature: fakeBase64(64) })),
    ...overrides,
  };
}

export const sampleCouncilEscrowRecord: CouncilEscrowRecordWire = {
  council_id: 'dinum',
  roster_version: 1,
  roster_hash: fakeBase64(32),
  threshold: 2,
  escrow_created_at_millis: 1_700_000_000_000,
  credential_auth_public_key_hash: fakeBase64(32),
  secret_commitment: fakeBase64(32),
  share_commitments: fakeBase64(64),
  shares: sampleCouncilMembers.map((m) => ({ slot: m.slot, capsule_hash: fakeBase64(32) })),
  escrow_signature: fakeBase64(64),
};

export const sampleCouncilEscrowBody: CouncilEscrowBody = {
  council_id: 'dinum',
  roster_version: 1,
  threshold: 2,
  credential: sampleVaultKeyring,
  escrow_created_at_millis: 1_700_000_000_000,
  secret_commitment: fakeBase64(32),
  share_commitments: fakeBase64(64),
  shares: sampleCouncilMembers.map((m) => ({ slot: m.slot, wrapped_share: fakeBase64(1200) })),
  escrow_signature: fakeBase64(64),
};
