/**
 * Emergency access (trusted contacts) vault operations. All privileged
 * (interface-only): they touch the VRK, the identity secret, or reveal a
 * recovery phrase.
 *
 * Trust model enforced here, stricter than the wrap-time share gate: creating
 * an escrow requires the contact's identity fingerprint to be `trusted` in the
 * grantor's TOFU registry (explicit out-of-band verification; `unknown` is NOT
 * enough to hand someone a way into the whole vault), and revealing a phrase
 * requires the GRANTOR's identity to be `trusted` in the contact's registry
 * (the escrow record is verified against that pinned identity, fail-closed, so
 * a server-forged escrow cannot trick a contact into printing a rogue kit).
 */
import {
  type EmergencyEscrowRecord,
  sha256,
  signEmergencyEscrow,
  unwrapPhraseEntropy,
  verifyEmergencyEscrow,
  wrapPhraseEntropyForGrantee,
} from '@encryption/src/crypto/emergency-escrow';
import { base64ToUint8, importPublicKeyFromBytes, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import { type MnemonicLanguage, keyToMnemonic, mnemonicToKey } from '@encryption/src/crypto/mnemonic';
import { activeIdentity } from '@encryption/src/crypto/vault-state';
import type { EmergencyDesignateBody, EmergencyEscrowRecordWire, EmergencyRearmEntry } from '@encryption/src/shared/schemas/emergency-access';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { fetchContinuityChain, handleFetchPublicKeys } from '@encryption/src/vault/operations/fetch-public-keys';
import { handleCheckFingerprints } from '@encryption/src/vault/operations/fingerprint-registry';
import { resolveContinuity } from '@encryption/src/vault/operations/identity-continuity';
import { deriveKeyring, loadWithIdentity } from '@encryption/src/vault/operations/onboarding';

// A single escrow payload (designation, or one re-arm entry minus its id).
// The emergency phrase never leaves this module: it is generated, wrapped to
// the contact, hashed into the signature, and discarded.
async function buildEscrowPayload(
  userId: string,
  granteeUserId: string,
  waitTimeDays: number,
  lang: MnemonicLanguage
): Promise<Omit<EmergencyDesignateBody, 'grantee_user_id' | 'wait_time_days'> & { grantee_user_id: string; wait_time_days: number }> {
  const { loaded, identitySecret } = await loadWithIdentity(userId);

  const { users } = await handleFetchPublicKeys(userId, { userIds: [granteeUserId] });
  const grantee = users[granteeUserId];

  if (!grantee || !grantee.verified || !grantee.encryptionPublicKey) {
    throw new VaultError(VaultErrorCode.UNTRUSTED_RECIPIENT, 'The contact has no verifiable directory record.');
  }

  // Stricter than the share gate: `unknown` is rejected. Escrowing a way into
  // the whole vault demands a prior explicit out-of-band verification.
  const { results } = await handleCheckFingerprints(
    userId,
    { userFingerprints: { [granteeUserId]: grantee.identityFingerprint } },
    { record: false }
  );
  if (results[0]?.status !== 'trusted') {
    throw new VaultError(VaultErrorCode.UNTRUSTED_RECIPIENT, 'Escrow requires an out-of-band verified (trusted) contact.');
  }

  const bundle = await deriveKeyring(userId, loaded.vrk, identitySecret, lang);
  const entropy = mnemonicToKey(bundle.recoveryPhrase, lang);
  const capsule = await wrapPhraseEntropyForGrantee(entropy, importPublicKeyFromBytes(new Uint8Array(grantee.encryptionPublicKey)));
  entropy.fill(0);

  const granteeIdentityPublicKeyWire = new Uint8Array(grantee.signaturePublicKey);
  const escrowCreatedAtMillis = Date.now();

  const record: EmergencyEscrowRecord = {
    grantorUserId: userId,
    granteeUserId,
    granteeIdentityPublicKeyWire,
    waitTimeDays,
    escrowCreatedAtMillis,
    credentialAuthPublicKeyHash: await sha256(base64ToUint8(bundle.keyring.auth_public_key)),
    capsuleHash: await sha256(capsule),
  };
  const signature = await signEmergencyEscrow(record, identitySecret);

  return {
    grantee_user_id: granteeUserId,
    wait_time_days: waitTimeDays,
    credential: bundle.keyring,
    grantee_identity_public_key: uint8ToBase64(granteeIdentityPublicKeyWire),
    grantee_key_version: grantee.version,
    wrapped_phrase_for_grantee: uint8ToBase64(capsule),
    escrow_signature: uint8ToBase64(signature),
    escrow_created_at_millis: escrowCreatedAtMillis,
  };
}

/** Designation (and standalone re-arm): returns the exact POST body for the interface. */
export async function handleCreateEmergencyEscrow(
  userId: string,
  payload: { granteeUserId: string; waitTimeDays: number; lang?: MnemonicLanguage }
): Promise<EmergencyDesignateBody> {
  return buildEscrowPayload(userId, payload.granteeUserId, payload.waitTimeDays, payload.lang ?? 'english');
}

/** Burn + re-arm payloads for the forced rotation after an emergency unlock (one fresh escrow per granted relationship). */
export async function handleBuildEmergencyRearms(
  userId: string,
  payload: { rearms: Array<{ emergencyAccessId: string; granteeUserId: string; waitTimeDays: number }>; lang?: MnemonicLanguage }
): Promise<{ rearms: EmergencyRearmEntry[] }> {
  const entries: EmergencyRearmEntry[] = [];

  for (const rearm of payload.rearms) {
    const built = await buildEscrowPayload(userId, rearm.granteeUserId, rearm.waitTimeDays, payload.lang ?? 'english');

    entries.push({
      emergency_access_id: rearm.emergencyAccessId,
      credential: built.credential,
      grantee_identity_public_key: built.grantee_identity_public_key,
      grantee_key_version: built.grantee_key_version,
      wrapped_phrase_for_grantee: built.wrapped_phrase_for_grantee,
      escrow_signature: built.escrow_signature,
      escrow_created_at_millis: built.escrow_created_at_millis,
    });
  }

  return { rearms: entries };
}

export type EscrowAuditStatus = 'ok' | 'tampered' | 'stale-identity' | 'outdated-key';

interface TrustedContactAuditInput {
  id: string;
  grantee_user_id: string;
  wait_time_days: number;
  escrow: EmergencyEscrowRecordWire;
}

/**
 * Audit the server-reported escrow list against local truth: every record must
 * verify under OUR identity key (a row we never signed, a swapped contact, an
 * altered wait time all fail), and each pinned contact identity is compared to
 * the directory (a contact who reset to an unlinked identity makes the escrow
 * unopenable: flag for renewal; a mere encryption-key rotation is only flagged
 * for a one-click re-arm, nothing is broken meanwhile).
 */
export async function handleVerifyEscrows(
  userId: string,
  payload: { contacts: TrustedContactAuditInput[] }
): Promise<{ results: Array<{ id: string; status: EscrowAuditStatus }> }> {
  const { loaded } = await loadWithIdentity(userId);
  const identity = activeIdentity(loaded.state);
  const identityRawKey = importPublicKeyFromBytes(base64ToUint8(identity!.signaturePublicKey));

  const granteeIds = [...new Set(payload.contacts.map((c) => c.grantee_user_id))];
  const { users } = granteeIds.length > 0 ? await handleFetchPublicKeys(userId, { userIds: granteeIds }) : { users: {} };

  const results: Array<{ id: string; status: EscrowAuditStatus }> = [];

  for (const contact of payload.contacts) {
    const record: EmergencyEscrowRecord = {
      grantorUserId: userId,
      granteeUserId: contact.grantee_user_id,
      granteeIdentityPublicKeyWire: base64ToUint8(contact.escrow.grantee_identity_public_key),
      waitTimeDays: contact.wait_time_days,
      escrowCreatedAtMillis: contact.escrow.escrow_created_at_millis,
      credentialAuthPublicKeyHash: base64ToUint8(contact.escrow.credential_auth_public_key_hash),
      capsuleHash: await sha256(base64ToUint8(contact.escrow.wrapped_phrase_for_grantee)),
    };

    const authentic = await verifyEmergencyEscrow(record, base64ToUint8(contact.escrow.escrow_signature), identityRawKey);
    if (!authentic) {
      results.push({ id: contact.id, status: 'tampered' });
      continue;
    }

    const directoryEntry = users[contact.grantee_user_id];
    if (directoryEntry && directoryEntry.verified) {
      const pinnedFingerprint = await computeKeyFingerprint(contact.escrow.grantee_identity_public_key);

      if (directoryEntry.identityFingerprint !== pinnedFingerprint) {
        // Changed identity: legitimate only when the continuity chain proves
        // the new one descends from the pinned one.
        const chain = await fetchContinuityChain(contact.grantee_user_id);
        const outcome = await resolveContinuity(contact.grantee_user_id, pinnedFingerprint, chain);

        if (!outcome.chained) {
          results.push({ id: contact.id, status: 'stale-identity' });
          continue;
        }
      }

      if (directoryEntry.version > contact.escrow.grantee_key_version) {
        results.push({ id: contact.id, status: 'outdated-key' });
        continue;
      }
    }

    results.push({ id: contact.id, status: 'ok' });
  }

  return { results };
}

/**
 * Contact side: open the released capsule and render the grantor's emergency
 * phrase for the printed handover kit. Everything stays in iframe memory; the
 * phrase is returned to the interface for display/print only, never persisted.
 */
export async function handleRevealEmergencyPhrase(
  userId: string,
  payload: { grantorUserId: string; lang: MnemonicLanguage; waitTimeDays: number; escrow: EmergencyEscrowRecordWire }
): Promise<{ recoveryPhrase: string }> {
  const { loaded } = await loadWithIdentity(userId);

  // The grantor identity the record is verified against comes from the
  // directory, but its TRUST comes from the contact's own registry: the
  // fingerprint must be pinned `trusted` (out-of-band verified). Fail-closed:
  // if the grantor was never verified, this is the moment it is enforced.
  const { users } = await handleFetchPublicKeys(userId, { userIds: [payload.grantorUserId] });
  const grantor = users[payload.grantorUserId];

  if (!grantor || !grantor.verified) {
    throw new VaultError(VaultErrorCode.UNTRUSTED_RECIPIENT, 'The vault owner has no verifiable directory record.');
  }

  const { results } = await handleCheckFingerprints(
    userId,
    { userFingerprints: { [payload.grantorUserId]: grantor.identityFingerprint } },
    { record: false }
  );
  if (results[0]?.status !== 'trusted') {
    throw new VaultError(VaultErrorCode.UNTRUSTED_RECIPIENT, 'Revealing a recovery phrase requires the vault owner to be verified (trusted).');
  }

  const record: EmergencyEscrowRecord = {
    grantorUserId: payload.grantorUserId,
    granteeUserId: userId,
    granteeIdentityPublicKeyWire: base64ToUint8(payload.escrow.grantee_identity_public_key),
    waitTimeDays: payload.waitTimeDays,
    escrowCreatedAtMillis: payload.escrow.escrow_created_at_millis,
    credentialAuthPublicKeyHash: base64ToUint8(payload.escrow.credential_auth_public_key_hash),
    capsuleHash: await sha256(base64ToUint8(payload.escrow.wrapped_phrase_for_grantee)),
  };

  const authentic = await verifyEmergencyEscrow(
    record,
    base64ToUint8(payload.escrow.escrow_signature),
    importPublicKeyFromBytes(new Uint8Array(grantor.signaturePublicKey))
  );
  if (!authentic) {
    throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'The escrow record does not verify against the vault owner identity.');
  }

  // Newest key first: grow-only history keeps older secrets for capsules
  // wrapped before a rotation.
  const secretKeys = [...loaded.state.encryptionKeys].sort((a, b) => b.version - a.version).map((entry) => base64ToUint8(entry.secretKey));
  if (secretKeys.length === 0) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'No encryption keys in this vault.');
  }

  const entropy = await unwrapPhraseEntropy(base64ToUint8(payload.escrow.wrapped_phrase_for_grantee), secretKeys);
  const recoveryPhrase = keyToMnemonic(entropy, payload.lang);
  entropy.fill(0);

  return { recoveryPhrase };
}
