import type { EmergencyDesignateBody } from '@encryption/src/shared/schemas/emergency-access';
import type { VaultItemWire, VaultKeyringWire } from '@encryption/src/shared/schemas/vault';
import type { GetApiPublicKeysResponses } from '@encryption/src/ui/api/generated/types.gen';

const DEMO_USER_ID = '00000000-0000-0000-0000-000000000000';

/** 128-bit identity fingerprint as 40 decimal digits (the verified-out-of-band value). */
export const sampleFingerprint = '0031712345678901234567890123456789012345';

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
