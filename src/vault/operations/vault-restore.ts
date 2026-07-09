/**
 * Cold-unlock restore: rebuild this device's vault from the server copy using
 * only the recovery phrase. This is the primary restore path — the server vault
 * IS the backup. No local key material is needed to start; the phrase derives
 * the KEK that (a) proves possession to the PoP gate and (b) unwraps the VRK.
 *
 * Flow: derive the KEK + auth key from the phrase, trying each of the account's
 * KDF variants (params are per-vault, not a single constant; see unlockVault),
 * and pass the server's PoP challenge, which self-selects whichever vault the
 * phrase unlocks (active or a dormant older one). Then receive the wrapped VRK +
 * sealed items, unwrap, verify the signed manifest against the vault's own
 * identity, and cache locally under a fresh non-extractable device key. A wrong
 * phrase yields a wrong auth key, so the server rejects the proof before any
 * ciphertext is released.
 */
import { generateDeviceKey, wrapVrkForDevice } from '@encryption/src/crypto/device-cache';
import { base64ToUint8, exportPublicKeyAsBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import type { SealedItem } from '@encryption/src/crypto/vault-manifest';
import { openState, verifyPulledVault } from '@encryption/src/crypto/vault-seal';
import { activeIdentity } from '@encryption/src/crypto/vault-state';
import { deriveKek, deriveVaultAuthKeyPair, signVaultChallenge, unwrapVrk } from '@encryption/src/crypto/vault-unlock';
import { BROADCAST_KEYS_CHANGED } from '@encryption/src/shared/constants';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { clearSymmetricKeyCache } from '@encryption/src/vault/symmetric-key-cache';
import { saveVaultCache, withVaultCacheLock } from '@encryption/src/vault/vault-cache';
import { deriveStoredKeyPair } from '@encryption/src/vault/vault-keys';

// Same origin as the API in production; the Vite proxy forwards /api in dev.
const API_BASE = '';

// The releasable content of a vault, returned by both /fetch and /reactivate.
interface VaultContentWire {
  vault_id: string;
  wrapped_vrk: string;
  revision: number;
  manifest: string | null;
  manifest_sig: string | null;
  items: Array<{ item_id: string; type: string; ciphertext: string; revision_date_millis: number }>;
}

interface VaultFetchWire extends VaultContentWire {
  is_active: boolean;
  created_at_millis: number;
}

// Prove possession of the recovery phrase to `endpoint` (/fetch or /reactivate)
// and return the KEK (to unwrap the VRK) plus the endpoint's response body.
//
// KDF params are PER-VAULT, not a single constant: a vault created before the
// standard was raised keeps its original params and must be derived with THOSE,
// not today's. Since the client can't know which vault a phrase unlocks until it
// derives, it asks the server for the account's distinct KDF variants and TRIES
// each (cheapest first, usually just one). One challenge is reused across attempts
// (a non-matching proof returns 401 and does NOT consume it; only a match does).
// The phrase's LANGUAGE is irrelevant: deriveKek hashes the normalized phrase
// STRING, so the user types their words (any wordlist) and the server self-selects
// the keyring built from that same string. A wrong phrase matches no variant.
async function unlockVault(userId: string, recoveryPhrase: string, token: string, endpoint: string): Promise<{ kek: Uint8Array; body: unknown }> {
  const auth = { Authorization: `Bearer ${token}` };

  const metaRes = await fetch(`${API_BASE}/api/vault/meta`, { headers: auth });
  if (metaRes.status === 404) throw new VaultError(VaultErrorCode.NOT_INITIALIZED, 'No vault to restore for this account.');
  if (!metaRes.ok) throw new VaultError(VaultErrorCode.UNKNOWN, `Vault meta failed: ${metaRes.status}`);
  const { kdf_variants: variants } = (await metaRes.json()) as { kdf_variants: Array<{ kdf_ops: number; kdf_mem: number }> };

  const chalRes = await fetch(`${API_BASE}/api/vault/challenge`, { method: 'POST', headers: auth });
  if (!chalRes.ok) throw new VaultError(VaultErrorCode.UNKNOWN, `Vault challenge failed: ${chalRes.status}`);
  const chal = (await chalRes.json()) as { challenge_id: string; nonce: string };
  const nonce = base64ToUint8(chal.nonce);

  for (const variant of variants) {
    const kek = await deriveKek(recoveryPhrase, userId, { opsLimit: variant.kdf_ops, memLimit: variant.kdf_mem });
    const authKeyPair = await deriveVaultAuthKeyPair(kek);
    const proof = uint8ToBase64(await signVaultChallenge(nonce, userId, authKeyPair.secretKey));

    const res = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers: { ...auth, 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge_id: chal.challenge_id, proof }),
    });

    if (res.ok) return { kek, body: await res.json() };
    // 401 = this variant's proof matched no keyring; try the next. Anything else
    // is a real transport/server error.
    if (res.status !== 401) throw new VaultError(VaultErrorCode.UNKNOWN, `Vault unlock failed: ${res.status}`);
  }

  // No variant matched: the phrase is wrong (or for the wrong account).
  throw new VaultError(VaultErrorCode.WRONG_SECRET_KEY, 'Wrong recovery phrase.');
}

// Unwrap the VRK, open + verify the sealed vault, and cache it locally under a
// fresh non-extractable device key. This is the ONLY place a recovered vault is
// persisted to this device, so it runs only for the vault that is (or has just
// become) the current one. Returns the vault's public keys. Throws on a bad KEK
// or a failed integrity check, before anything is written.
async function openAndCacheVault(
  userId: string,
  kek: Uint8Array,
  vault: VaultContentWire
): Promise<{ publicKey: string; signaturePublicKey: string }> {
  let vrk: Uint8Array;
  try {
    vrk = await unwrapVrk(base64ToUint8(vault.wrapped_vrk), kek);
  } catch {
    throw new VaultError(VaultErrorCode.WRONG_SECRET_KEY, 'Wrong recovery phrase.');
  }

  const sealed: SealedItem[] = vault.items.map((i) => ({
    id: i.item_id,
    // Server-provided and covered by the signed manifest (verified below), so we
    // narrow here; an unrecognized future type is simply ignored by itemsToState.
    type: i.type as SealedItem['type'],
    revisionDate: i.revision_date_millis,
    ciphertext: i.ciphertext,
  }));
  const state = await openState(sealed, vrk);
  const identity = activeIdentity(state);
  if (!identity) throw new VaultError(VaultErrorCode.MISSING_KEYS, 'The restored vault has no identity.');

  // Verify the signed manifest against the vault's own identity (fail closed).
  // lastSeenRevision -1 means "first sight", so no rollback check applies. Every
  // bootstrapped vault has a manifest (VaultMeta.manifest is non-nullable), so a
  // missing one can only mean a tampering or lossy server: refuse it rather than
  // cache an unverified, potentially spliced item set.
  if (!vault.manifest || !vault.manifest_sig) {
    throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'The restored vault is missing its signed manifest.');
  }

  const ok = await verifyPulledVault(sealed, vault.manifest, vault.manifest_sig, base64ToUint8(identity.signaturePublicKey), -1);
  if (!ok) throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'The restored vault failed its integrity check.');

  const deviceKey = await generateDeviceKey();
  const wrappedVrk = await wrapVrkForDevice(vrk, deviceKey);
  await withVaultCacheLock(userId, () =>
    saveVaultCache(userId, {
      deviceKey,
      wrappedVrk,
      sealed,
      manifest: vault.manifest,
      manifestSig: vault.manifest_sig,
      revision: vault.revision,
    })
  );

  // Switched to a (possibly different) vault: purge symmetric keys cached under
  // the previous keyring so they aren't reused against this one.
  clearSymmetricKeyCache();

  getVaultBroadcastChannel()?.postMessage({ type: BROADCAST_KEYS_CHANGED });

  const pair = deriveStoredKeyPair(state)!;

  return {
    publicKey: exportPublicKeyAsBase64(pair.publicKey),
    signaturePublicKey: exportPublicKeyAsBase64(pair.signaturePublicKey),
  };
}

export async function handleRestoreFromPhrase(
  userId: string,
  payload: { recoveryPhrase: string; token: string }
): Promise<{ publicKey: string; signaturePublicKey: string; isActiveVault: boolean; vaultCreatedAtMillis: number }> {
  const { kek, body } = await unlockVault(userId, payload.recoveryPhrase, payload.token, '/api/vault/fetch');
  const vault = body as VaultFetchWire;

  // A DORMANT vault is NOT persisted here. Bringing it back demotes the current
  // vault, so it is an explicit, user-confirmed step (handleReactivateVault),
  // and only that step caches. We just report that the phrase unlocked a dormant
  // vault (the successful fetch already proved the phrase), changing nothing
  // locally so a cancel leaves this device exactly as it was.
  if (!vault.is_active) {
    return { publicKey: '', signaturePublicKey: '', isActiveVault: false, vaultCreatedAtMillis: vault.created_at_millis };
  }

  const { publicKey, signaturePublicKey } = await openAndCacheVault(userId, kek, vault);

  return { publicKey, signaturePublicKey, isActiveVault: true, vaultCreatedAtMillis: vault.created_at_millis };
}

/**
 * Bring the vault a recovery phrase unlocks back as the current one. Used after
 * a restore reported `isActiveVault: false`, once the user has confirmed the
 * switch. The server flips the vault active (and demotes the previous one), then
 * returns its content, which we open and cache here. This is the first and only
 * point at which anything is written to this device, so a cancelled confirmation
 * leaves no trace. Returns the new public keys plus which vault was demoted.
 *
 * This re-runs the full unlock (re-derives the KEK from the phrase) rather than
 * reusing what the preceding /fetch already derived. That is deliberate: the
 * derivation happens in the vault iframe, but the confirmation modal lives in the
 * interface (a separate context, reached over postMessage), so reusing it would
 * mean the vault holds the passphrase-derived KEK/authKey in memory across an
 * open-ended user interaction. Re-deriving keeps the vault stateless between the
 * two ops; the second Argon2 is a one-off cost on a rare, user-confirmed action.
 */
export async function handleReactivateVault(
  userId: string,
  payload: { recoveryPhrase: string; token: string }
): Promise<{
  reactivated: boolean;
  publicKey: string;
  signaturePublicKey: string;
  disabledVaultId: string | null;
  disabledVaultCreatedAtMillis: number | null;
}> {
  const { kek, body } = await unlockVault(userId, payload.recoveryPhrase, payload.token, '/api/vault/reactivate');
  const data = body as VaultContentWire & {
    reactivated: boolean;
    disabled_vault_id: string | null;
    disabled_vault_created_at_millis: number | null;
  };

  const { publicKey, signaturePublicKey } = await openAndCacheVault(userId, kek, data);

  return {
    reactivated: data.reactivated,
    publicKey,
    signaturePublicKey,
    disabledVaultId: data.disabled_vault_id ?? null,
    disabledVaultCreatedAtMillis: data.disabled_vault_created_at_millis ?? null,
  };
}
