import 'fake-indexeddb/auto';
import sodium from 'libsodium-wrappers-sumo';

import { base64ToUint8 } from '@encryption/src/crypto/encryption-backup';
import { verifyManifest } from '@encryption/src/crypto/vault-manifest';
import { activeIdentity } from '@encryption/src/crypto/vault-state';
import { DEFAULT_KDF_PARAMS, deriveKek, deriveVaultAuthKeyPair, unwrapVrk, verifyAuthPublicKeyBinding } from '@encryption/src/crypto/vault-unlock';
import { closeVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { handleGenerateKeys } from '@encryption/src/vault/operations/generate-keys';
import { handleChangeRecoveryPhrase, handlePrepareOnboarding } from '@encryption/src/vault/operations/onboarding';
import { loadVault } from '@encryption/src/vault/vault-keys';

beforeAll(async () => {
  await sodium.ready;
});

afterAll(() => {
  closeVaultBroadcastChannel();
});

describe('onboarding bundle builder', () => {
  it('produces a body that every downstream verifier will accept', async () => {
    const userId = 'u-onboard';
    await handleGenerateKeys(userId);

    const bundle = await handlePrepareOnboarding(userId, { lang: 'english' });

    const loaded = await loadVault(userId);
    const identityPub = base64ToUint8(activeIdentity(loaded!.state)!.signaturePublicKey);

    // Recovery phrase is a 24-word BIP-39 mnemonic.
    expect(bundle.recoveryPhrase.trim().split(/\s+/)).toHaveLength(24);
    expect(bundle.keyring.lang).toBe('english');
    expect(bundle.keyring.kdf_ops).toBe(DEFAULT_KDF_PARAMS.opsLimit);
    expect(bundle.keyring.kdf_mem).toBe(DEFAULT_KDF_PARAMS.memLimit);

    // The wrapped VRK unwraps, with the phrase-derived KEK, back to the live VRK.
    const kek = await deriveKek(bundle.recoveryPhrase, userId);
    const unwrapped = await unwrapVrk(base64ToUint8(bundle.keyring.wrapped_vrk), kek);
    expect(Buffer.from(unwrapped)).toEqual(Buffer.from(loaded!.vrk));

    // The auth public key is exactly the one the server's PoP gate will verify.
    const authKeyPair = await deriveVaultAuthKeyPair(kek);
    expect(bundle.keyring.auth_public_key).toBe(sodium.to_base64(authKeyPair.publicKey, sodium.base64_variants.ORIGINAL));

    // The identity binds that auth public key (anti-tamper on the keyring), via
    // the domain-separated binding the server verifies.
    const bindingOk = await verifyAuthPublicKeyBinding(authKeyPair.publicKey, base64ToUint8(bundle.keyring.auth_pub_sig), identityPub);
    expect(bindingOk).toBe(true);

    // The manifest is signed by the identity and pinned at the server's revision 1.
    const manifest = JSON.parse(bundle.manifest);
    expect(manifest.revision).toBe(1);
    expect(await verifyManifest(manifest, bundle.manifestSig, identityPub)).toBe(true);

    // The item set is non-empty (identity + encryption key + active pointer).
    expect(bundle.items.length).toBeGreaterThanOrEqual(3);
  });

  it('refuses to build before keys are generated', async () => {
    await expect(handlePrepareOnboarding('u-no-keys', {})).rejects.toThrow();
  });
});

describe('change passphrase', () => {
  it('re-wraps the same VRK under a new phrase and rotates the auth key', async () => {
    const userId = 'u-change';
    await handleGenerateKeys(userId);
    const before = await handlePrepareOnboarding(userId, { lang: 'english' });

    const after = await handleChangeRecoveryPhrase(userId, { lang: 'english' });

    // A genuinely new phrase, so a genuinely new wrapping and auth key.
    expect(after.recoveryPhrase).not.toBe(before.recoveryPhrase);
    expect(after.keyring.auth_public_key).not.toBe(before.keyring.auth_public_key);

    // But it still unwraps to the SAME VRK — the documents are untouched.
    const vrk = (await loadVault(userId))!.vrk;
    const kek = await deriveKek(after.recoveryPhrase, userId);
    const unwrapped = await unwrapVrk(base64ToUint8(after.keyring.wrapped_vrk), kek);
    expect(Buffer.from(unwrapped)).toEqual(Buffer.from(vrk));
  });
});
