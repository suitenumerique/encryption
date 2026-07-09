/**
 * The single seam between the vault's runtime key operations and the
 * synchronized VaultState. Key material lives as sealed items in the vault
 * cache (sealed under the VRK, which is wrapped by the non-extractable device
 * key), never in plaintext. Every key operation goes through here:
 *
 *   - `loadVault` opens the cached state (unwrapping the VRK with the device key)
 *   - `deriveStoredKeyPair` projects the active identity + encryption key back
 *     into the raw-libsodium shape the crypto operations expect
 *   - `createVault` / `mutateVault` are the only writers
 *
 * Keeping the derivation here means the many callers (encrypt, decrypt, sign,
 * backup, has-keys) keep the exact same `StoredKeyPair` contract they always
 * had — only the backing store changed.
 */
import type { HybridPublicKey, HybridSecretKey, SignaturePublicKey, SignatureSecretKey, UserKeyBundle } from '@encryption/src/crypto';
import { generateDeviceKey, unwrapVrkForDevice, wrapVrkForDevice } from '@encryption/src/crypto/device-cache';
import { base64ToUint8, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { buildSignedManifest, openState, sealState } from '@encryption/src/crypto/vault-seal';
import {
  type VaultState,
  activeEncryptionKey,
  activeIdentity,
  addEncryptionKey,
  addIdentity,
  emptyVaultState,
} from '@encryption/src/crypto/vault-state';
import { generateVrk } from '@encryption/src/crypto/vault-unlock';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import {
  type VaultCacheEntry,
  getPersistedVaultCache,
  getVaultCache,
  saveVaultCache,
  stageVaultCache,
  withVaultCacheLock,
} from '@encryption/src/vault/vault-cache';

/**
 * The raw-libsodium key material for one identity, projected out of VaultState.
 * An encryption key is always minted under an identity, so the two always travel
 * together; {@link deriveStoredKeyPair} returns null rather than a half-populated
 * pair when either is missing.
 */
export interface StoredKeyPair {
  publicKey: HybridPublicKey;
  secretKey: HybridSecretKey;
  signaturePublicKey: SignaturePublicKey;
  signatureSecretKey: SignatureSecretKey;
}

export interface LoadedVault {
  state: VaultState;
  vrk: Uint8Array;
  cache: VaultCacheEntry;
}

export async function loadVault(userId: string, opts: { persistedOnly?: boolean } = {}): Promise<LoadedVault | null> {
  const cache = opts.persistedOnly ? await getPersistedVaultCache(userId) : await getVaultCache(userId);

  if (!cache) return null;

  const vrk = await unwrapVrkForDevice(cache.wrappedVrk, cache.deviceKey);
  const state = cache.sealed.length > 0 ? await openState(cache.sealed, vrk) : emptyVaultState();

  return { state, vrk, cache };
}

/** Project the active identity + encryption key back into raw-libsodium bytes. */
export function deriveStoredKeyPair(state: VaultState): StoredKeyPair | null {
  const enc = activeEncryptionKey(state);
  const id = activeIdentity(state);

  if (!enc || !id) return null;

  return {
    publicKey: base64ToUint8(enc.publicKey),
    secretKey: base64ToUint8(enc.secretKey),
    signaturePublicKey: base64ToUint8(id.signaturePublicKey),
    signatureSecretKey: base64ToUint8(id.signatureSecretKey),
  };
}

// Reseal + persist the state, keeping the same device key / wrapped VRK /
// revision. The local manifest is rebuilt so a warm read stays coherent; it is
// re-signed by the active identity (a state with no identity leaves the prior
// manifest untouched, which never happens for a real vault).
async function persist(userId: string, cache: VaultCacheEntry, state: VaultState, vrk: Uint8Array): Promise<void> {
  const sealed = await sealState(state, vrk);
  const identity = activeIdentity(state);

  let { manifest, manifestSig } = cache;

  if (identity) {
    const built = await buildSignedManifest(cache.revision, state.active.identityGen, sealed, base64ToUint8(identity.signatureSecretKey));
    manifest = built.manifest;
    manifestSig = built.manifestSig;
  }

  await saveVaultCache(userId, { ...cache, sealed, manifest, manifestSig });
}

/**
 * Create a brand-new local vault for a freshly minted or restored key bundle:
 * a random VRK sealed under a fresh non-extractable device key, with the bundle
 * as the active identity + encryption key. `revision` starts at 0 (never pushed
 * to the server yet); onboarding / sync assigns the server revision.
 *
 * `version` / `generation` default to 1 (a first onboarding). A restore of an
 * already-registered key must pass the registered version so the sealed item id
 * (`enc:<version>`) matches what the server holds.
 */
export async function createVault(
  userId: string,
  bundle: UserKeyBundle,
  opts: { version?: number; generation?: number; createdAt?: number } = {}
): Promise<VaultState> {
  const version = opts.version ?? 1;
  const generation = opts.generation ?? 1;
  const createdAt = opts.createdAt ?? Date.now();

  const vrk = await generateVrk();
  const deviceKey = await generateDeviceKey();
  const wrappedVrk = await wrapVrkForDevice(vrk, deviceKey);

  let state = emptyVaultState();
  state = addIdentity(state, {
    generation,
    algo: 'ed25519',
    signaturePublicKey: uint8ToBase64(bundle.signature.publicKey),
    signatureSecretKey: uint8ToBase64(bundle.signature.secretKey),
    createdAt,
  });
  state = addEncryptionKey(state, {
    version,
    algo: 'x-wing',
    publicKey: uint8ToBase64(bundle.encryption.publicKey),
    secretKey: uint8ToBase64(bundle.encryption.secretKey),
    createdAt,
  });

  const sealed = await sealState(state, vrk);
  const { manifest, manifestSig } = await buildSignedManifest(0, generation, sealed, bundle.signature.secretKey);
  const entry: VaultCacheEntry = { deviceKey, wrappedVrk, sealed, manifest, manifestSig, revision: 0 };

  // A freshly created vault is ALWAYS staged in memory, never written to disk
  // here. Creating a vault only happens during onboarding, which must first show
  // the recovery phrase for backup; the vault is persisted (commitStagedVault)
  // only once that backup is confirmed and the server registration succeeds. This
  // is the sole path that creates a vault, so there is no "persist now" variant.
  stageVaultCache(userId, entry);

  return state;
}

/**
 * Load, apply a pure mutation to the state, then reseal + persist. The whole
 * read-modify-write runs under the per-user cache lock so a concurrent writer
 * (another tab's mutation, or a sync) can't clobber it.
 */
export async function mutateVault(userId: string, mutate: (state: VaultState) => VaultState): Promise<VaultState> {
  return withVaultCacheLock(userId, async () => {
    const loaded = await loadVault(userId);

    if (!loaded) {
      throw new VaultError(VaultErrorCode.NOT_INITIALIZED, 'No synchronized vault on this device.');
    }

    const next = mutate(loaded.state);
    await persist(userId, loaded.cache, next, loaded.vrk);

    return next;
  });
}

/**
 * Relabel a freshly created vault's single identity/encryption key to the
 * server-assigned generation/version before it is sealed for the bootstrap.
 * `createVault` defaults to 1/1, which is correct for a first onboarding; a
 * re-onboard after a reset must adopt `max + 1` so the sealed `enc:<version>` /
 * `identity:<generation>` items line up with the directory. No-op when the
 * numbers already match.
 */
export async function reversionFreshVault(userId: string, version?: number, generation?: number): Promise<void> {
  await mutateVault(userId, (state) => {
    const identity = activeIdentity(state);
    const encryptionKey = activeEncryptionKey(state);
    if (!identity || !encryptionKey) return state;

    const nextGeneration = generation ?? identity.generation;
    const nextVersion = version ?? encryptionKey.version;
    if (nextGeneration === identity.generation && nextVersion === encryptionKey.version) return state;

    return {
      ...state,
      identities: state.identities.map((e) => (e.generation === state.active.identityGen ? { ...e, generation: nextGeneration } : e)),
      encryptionKeys: state.encryptionKeys.map((e) => (e.version === state.active.encKeyVersion ? { ...e, version: nextVersion } : e)),
      active: { identityGen: nextGeneration, encKeyVersion: nextVersion },
    };
  });
}

/**
 * True when this device holds a COMMITTED vault with an active encryption key.
 * Reads persisted state only: a staged onboarding vault (minted locally but not
 * yet registered on the server) must report false, so a product never treats an
 * un-registered user as ready.
 */
export async function hasVaultKeys(userId: string): Promise<boolean> {
  const loaded = await loadVault(userId, { persistedOnly: true });

  return loaded !== null && activeEncryptionKey(loaded.state) !== undefined;
}
