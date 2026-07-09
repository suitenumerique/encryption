/**
 * Builds what the atomic `POST /api/vault` bootstrap and the change-recovery-phrase
 * flow need from the local vault: a high-entropy recovery phrase, the VRK wrapped
 * under the phrase-derived KEK, and the phrase-derived auth public key with an
 * identity binding. Onboarding additionally carries the sealed items + a signed
 * manifest at the server's first revision.
 *
 * The recovery phrase is generated here and returned so the interface can show
 * it once as the Recovery Kit; it is never stored. `generate-keys` must have run
 * first (this reads the local vault it created).
 */
import { base64ToUint8, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import type { MnemonicLanguage } from '@encryption/src/crypto/mnemonic';
import type { SignatureSecretKey } from '@encryption/src/crypto/signature';
import { buildSignedManifest } from '@encryption/src/crypto/vault-seal';
import { activeIdentity } from '@encryption/src/crypto/vault-state';
import {
  DEFAULT_KDF_PARAMS,
  deriveKek,
  deriveVaultAuthKeyPair,
  generateRecoveryPhrase,
  signAuthPublicKeyBinding,
  wrapVrk,
} from '@encryption/src/crypto/vault-unlock';
import type { VaultItemWire, VaultKeyringWire } from '@encryption/src/shared/schemas/vault';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { type LoadedVault, loadVault, reversionFreshVault } from '@encryption/src/vault/vault-keys';

// The server assigns accountRevision 1 to a freshly bootstrapped vault, so the
// manifest the client signs must carry that same revision.
const BOOTSTRAP_REVISION = 1;

export interface OnboardingBundle {
  recoveryPhrase: string; // shown once as the Recovery Kit; never persisted
  keyring: VaultKeyringWire;
  items: VaultItemWire[];
  manifest: string;
  manifestSig: string;
}

export interface KeyringBundle {
  recoveryPhrase: string;
  keyring: VaultKeyringWire;
}

async function loadWithIdentity(userId: string): Promise<{ loaded: LoadedVault; identitySecret: SignatureSecretKey }> {
  const loaded = await loadVault(userId);

  if (!loaded) {
    throw new VaultError(VaultErrorCode.NOT_INITIALIZED, 'Generate keys before touching the vault keyring.');
  }

  const identity = activeIdentity(loaded.state);

  if (!identity) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'The local vault has no active identity.');
  }

  return { loaded, identitySecret: base64ToUint8(identity.signatureSecretKey) };
}

// A recovery phrase -> KEK -> wraps the VRK (VRK indirection: the phrase never
// touches the items, so a passphrase change is a cheap re-wrap). The auth key
// pair is derived from the same KEK and is what the server's PoP gate checks;
// the identity binds its public key so a tampered keyring is detectable. An
// existing `reusePhrase` reproduces the same keyring (used when a commit retries
// after a version conflict, so the phrase the user already saved stays valid).
async function deriveKeyring(
  userId: string,
  vrk: Uint8Array,
  identitySecret: SignatureSecretKey,
  lang: MnemonicLanguage,
  reusePhrase?: string
): Promise<KeyringBundle> {
  const recoveryPhrase = reusePhrase ?? (await generateRecoveryPhrase(lang));
  const kek = await deriveKek(recoveryPhrase, userId);
  const wrappedVrk = await wrapVrk(vrk, kek);
  const authKeyPair = await deriveVaultAuthKeyPair(kek);
  const authPubSig = await signAuthPublicKeyBinding(authKeyPair.publicKey, identitySecret);

  return {
    recoveryPhrase,
    keyring: {
      wrapped_vrk: uint8ToBase64(wrappedVrk),
      auth_public_key: uint8ToBase64(authKeyPair.publicKey),
      auth_pub_sig: uint8ToBase64(authPubSig),
      kdf_ops: DEFAULT_KDF_PARAMS.opsLimit,
      kdf_mem: DEFAULT_KDF_PARAMS.memLimit,
      lang,
    },
  };
}

export async function handlePrepareOnboarding(
  userId: string,
  payload: { lang?: MnemonicLanguage; version?: number; generation?: number; reusePhrase?: string }
): Promise<OnboardingBundle> {
  // Adopt the server-assigned version/generation before sealing, so a re-onboard
  // after a reset (or a commit retry after a version conflict) seals items that
  // match the directory (no-op on a first onboard).
  if (payload.version !== undefined || payload.generation !== undefined) {
    await reversionFreshVault(userId, payload.version, payload.generation);
  }

  const { loaded, identitySecret } = await loadWithIdentity(userId);
  const lang: MnemonicLanguage = payload.lang ?? 'english';

  const { recoveryPhrase, keyring } = await deriveKeyring(userId, loaded.vrk, identitySecret, lang, payload.reusePhrase);

  const sealed = loaded.cache.sealed;
  const { manifest, manifestSig } = await buildSignedManifest(BOOTSTRAP_REVISION, loaded.state.active.identityGen, sealed, identitySecret);

  return {
    recoveryPhrase,
    keyring,
    items: sealed.map((s) => ({ item_id: s.id, type: s.type, ciphertext: s.ciphertext, revision_date_millis: s.revisionDate })),
    manifest,
    manifestSig,
  };
}

// Change the recovery phrase: re-derive the keyring under a brand-new phrase.
// The VRK (and therefore every sealed item) is untouched — only its wrapping and
// the auth key change, so the interface just PUTs the returned keyring.
export async function handleChangeRecoveryPhrase(userId: string, payload: { lang?: MnemonicLanguage }): Promise<KeyringBundle> {
  const { loaded, identitySecret } = await loadWithIdentity(userId);
  const lang: MnemonicLanguage = payload.lang ?? 'english';

  return deriveKeyring(userId, loaded.vrk, identitySecret, lang);
}
