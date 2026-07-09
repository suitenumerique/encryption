/**
 * Device-approval orchestration inside the vault iframe. Two roles:
 *
 *   New device  — mints an ephemeral X-Wing key pair (`start`), then, once an
 *                 enrolled device has forwarded the VRK wrapped to it, unwraps it
 *                 and adopts the vault locally (`complete`).
 *   Enrolled    — verifies the new device's public-key fingerprint against the
 *                 pairing code and wraps the VRK to it (`approve`).
 *
 * The ephemeral secret key stays in memory on the new device between `start` and
 * `complete` (same iframe session); it is never persisted or sent anywhere.
 */
import { type HybridSecretKey, generateUserKeyPair } from '@encryption/src/crypto';
import { generateDeviceKey, wrapVrkForDevice } from '@encryption/src/crypto/device-cache';
import { base64ToUint8, exportPublicKeyAsBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { openState, verifyPulledVault } from '@encryption/src/crypto/vault-seal';
import { activeIdentity } from '@encryption/src/crypto/vault-state';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { deviceKeyDecimalFingerprint, unwrapBootstrapOnNewDevice, wrapBootstrapForNewDevice } from '@encryption/src/vault/operations/device-approval';
import { createRequestSigner } from '@encryption/src/vault/operations/request-signer';
import { createHttpSyncTransport } from '@encryption/src/vault/operations/vault-sync-transport';
import { clearSymmetricKeyCache } from '@encryption/src/vault/symmetric-key-cache';
import { saveVaultCache, withVaultCacheLock } from '@encryption/src/vault/vault-cache';
import { loadVault } from '@encryption/src/vault/vault-keys';

// The new device's ephemeral key pair, held only between start and complete.
let pendingEphemeral: { publicKeyB64: string; secretKey: HybridSecretKey } | null = null;

/**
 * New device: mint the ephemeral key and return its FULL public key (for the QR)
 * plus the decimal fingerprint (for the no-camera manual fallback).
 */
export async function handleStartDeviceApproval(): Promise<{ devicePublicKey: string; decimalFingerprint: string }> {
  const keyPair = await generateUserKeyPair();
  const publicKeyB64 = exportPublicKeyAsBase64(keyPair.publicKey);

  pendingEphemeral = { publicKeyB64, secretKey: keyPair.secretKey };

  return { devicePublicKey: publicKeyB64, decimalFingerprint: await deviceKeyDecimalFingerprint(publicKeyB64) };
}

/**
 * New device: unwrap the forwarded VRK with the ephemeral secret, then adopt the
 * vault by pulling its sealed items and caching them under a fresh device key.
 */
export async function handleCompleteDeviceApproval(
  userId: string,
  payload: { wrappedDeviceBootstrap: string; token?: string | null }
): Promise<{ adopted: boolean }> {
  if (!pendingEphemeral) {
    throw new VaultError(VaultErrorCode.NOT_INITIALIZED, 'No pending device approval on this device.');
  }

  const { vrk, identitySecretKey } = await unwrapBootstrapOnNewDevice(base64ToUint8(payload.wrappedDeviceBootstrap), pendingEphemeral.secretKey);

  // Pull the vault and verify the signed manifest against the identity carried
  // inside it (the same fail-closed check restore does) before adopting it. This
  // stops a lazy or garbage-serving server: the manifest must be self-consistent
  // with the state it accompanies.
  //
  // It does NOT, and cannot, prove the adopted identity is the user's REAL one.
  // The VRK is wrapped with unauthenticated public-key encryption to this device's
  // ephemeral key, so a fully malicious server could wrap its own VRK' and serve a
  // self-consistent vault under an attacker identity, and this check would pass.
  // That is not a pairing-specific hole: it is the general case of an untrusted
  // server substituting a user's identity, which the system answers everywhere the
  // same way, out-of-band fingerprint verification between contacts (TOFU) plus
  // identity reconciliation, not inside this flow. A brand-new device has no prior
  // anchor to detect it itself, and we deliberately do NOT add a second
  // out-of-band confirmation step.
  // The forwarded identity key signs this very first pull (a covered route): the
  // new device does not yet hold the vault it is about to fetch, so it could not
  // otherwise produce the required identity signature.
  const pulled = await createHttpSyncTransport({
    token: payload.token ?? null,
    signRequest: createRequestSigner(identitySecretKey, userId),
  }).fetch();

  if (!pulled) {
    throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'The vault to adopt is empty or unsigned on the server.');
  }

  const state = await openState(pulled.sealed, vrk);
  const identity = activeIdentity(state);

  if (!identity) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'The vault to adopt has no identity.');
  }

  const ok = await verifyPulledVault(pulled.sealed, pulled.manifest, pulled.manifestSig, base64ToUint8(identity.signaturePublicKey), -1);

  if (!ok) {
    throw new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'The vault to adopt failed its integrity check.');
  }

  const deviceKey = await generateDeviceKey();
  const wrappedVrk = await wrapVrkForDevice(vrk, deviceKey);

  await withVaultCacheLock(userId, () =>
    saveVaultCache(userId, {
      deviceKey,
      wrappedVrk,
      sealed: pulled.sealed,
      manifest: pulled.manifest,
      manifestSig: pulled.manifestSig,
      revision: pulled.revision,
    })
  );

  // Only now that the vault is persisted do we drop the ephemeral secret. Any
  // failure above (network, integrity) leaves it in place so the UI can retry
  // completion with the wrapped VRK it still holds, instead of forcing the user
  // to restart the whole pairing.
  pendingEphemeral = null;

  // Adopted a vault from another device: drop any keys cached under a prior one.
  clearSymmetricKeyCache();

  return { adopted: true };
}

/**
 * Enrolled device: wrap the VRK for the new device. `devicePublicKey` is the key
 * the server returned for the pending request; `expectedDecimal` is the fingerprint
 * carried over out-of-band (QR scan or typed). We refuse unless the server key's
 * decimal fingerprint matches it (the "server swapped the key" case).
 */
export async function handleApproveDevice(
  userId: string,
  payload: { devicePublicKey: string; expectedDecimal: string }
): Promise<{ wrappedDeviceBootstrap: string }> {
  const loaded = await loadVault(userId);

  if (!loaded) {
    throw new VaultError(VaultErrorCode.NOT_INITIALIZED, 'No vault on this device to forward.');
  }

  const identity = activeIdentity(loaded.state);

  if (!identity) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'This device has no active identity to forward.');
  }

  const wrapped = await wrapBootstrapForNewDevice(
    loaded.vrk,
    base64ToUint8(identity.signatureSecretKey),
    payload.devicePublicKey,
    payload.expectedDecimal
  );

  if (!wrapped) {
    throw new VaultError(VaultErrorCode.INVALID_KEY_BINDING, 'Device key fingerprint mismatch.');
  }

  return { wrappedDeviceBootstrap: uint8ToBase64(wrapped) };
}
