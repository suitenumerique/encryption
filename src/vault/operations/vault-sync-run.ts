/**
 * Runs one synchronization pass from inside the vault iframe: unwrap the cached
 * VRK with the device key, open the local sealed state, pull-merge-push against
 * the server, then reseal and persist the converged state. Only a status and
 * the agreed revision cross the postMessage boundary — never key material.
 *
 * The interface triggers this (it owns the OIDC token, passed in `payload`);
 * a server-push "revision changed" wake or a cross-tab broadcast is what makes
 * the interface call it.
 */
import { unwrapVrkForDevice } from '@encryption/src/crypto/device-cache';
import { base64ToUint8 } from '@encryption/src/crypto/encryption-backup';
import { buildSignedManifest, openState, sealState } from '@encryption/src/crypto/vault-seal';
import { type VaultState, activeIdentity, emptyVaultState } from '@encryption/src/crypto/vault-state';
import { BROADCAST_KEYS_CHANGED } from '@encryption/src/shared/constants';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { createRequestSigner } from '@encryption/src/vault/operations/request-signer';
import { type SyncCrypto, sync } from '@encryption/src/vault/operations/vault-sync';
import { createHttpSyncTransport } from '@encryption/src/vault/operations/vault-sync-transport';
import { getVaultCache, saveVaultCache, withVaultCacheLock } from '@encryption/src/vault/vault-cache';

interface SyncPayload {
  /** OIDC token: no longer required for the sync data-plane (it authenticates by
   *  identity signature), kept optional for callers that still have one. */
  token?: string | null;
  /** Optional WRITE-THROUGH mutation: applied to the opened state BEFORE the push,
   *  so the change is only persisted locally if the push succeeds. */
  mutate?: (state: VaultState) => VaultState;
}

export async function handleSync(userId: string, payload: SyncPayload = {}): Promise<{ status: string; revision: number }> {
  // Hold the per-user cache lock across the whole pull-merge-push-save: the save
  // at the end reseals a state opened at the start, so a mutation (e.g. a TOFU
  // decision from another tab) landing in between would otherwise be discarded.
  return withVaultCacheLock(userId, () => runSync(userId, payload));
}

async function runSync(userId: string, payload: SyncPayload): Promise<{ status: string; revision: number }> {
  const cache = await getVaultCache(userId);

  if (!cache) {
    // No device key / wrapped VRK on this device yet: it hasn't been enrolled
    // (onboarding or device approval sets the cache up).
    throw new VaultError(VaultErrorCode.NOT_INITIALIZED, 'This device has no synchronized vault to sync.');
  }

  const vrk = await unwrapVrkForDevice(cache.wrappedVrk, cache.deviceKey);
  const opened = cache.sealed.length > 0 ? await openState(cache.sealed, vrk) : emptyVaultState();

  const identity = activeIdentity(opened);

  if (!identity) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'The cached vault has no active identity to sign with.');
  }

  const crypto: SyncCrypto = {
    vrk,
    identitySecretKey: base64ToUint8(identity.signatureSecretKey),
    // The device trusts its own identity, so it verifies pulls against it.
    trustedIdentityPublicKey: base64ToUint8(identity.signaturePublicKey),
    identityGen: opened.active.identityGen,
  };

  // Apply the write-through mutation IN MEMORY. It is persisted only if `sync`
  // (which saves the converged state at the end) succeeds; a failed push leaves
  // the cache untouched, so a local change is never kept without a server commit.
  const localState = payload.mutate ? payload.mutate(opened) : opened;

  const transport = createHttpSyncTransport({
    token: payload?.token ?? null,
    signRequest: createRequestSigner(crypto.identitySecretKey, userId),
  });
  const result = await sync(localState, cache.revision, transport, crypto);

  if (result.status === 'ok') {
    // Reseal the converged state and rebuild the manifest at the agreed
    // revision, so the next warm start verifies against exactly these bytes.
    const sealed = await sealState(result.state, vrk);
    const { manifest, manifestSig } = await buildSignedManifest(result.revision, crypto.identityGen, sealed, crypto.identitySecretKey);

    await saveVaultCache(userId, { ...cache, sealed, manifest, manifestSig, revision: result.revision });

    // Nudge other tabs to reload their in-memory view from the fresh cache.
    getVaultBroadcastChannel()?.postMessage({ type: BROADCAST_KEYS_CHANGED });

    return { status: 'ok', revision: result.revision };
  }

  return { status: result.status, revision: cache.revision };
}
