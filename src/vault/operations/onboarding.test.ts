import 'fake-indexeddb/auto';
import sodium from 'libsodium-wrappers-sumo';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { base64ToUint8, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { verifyManifest } from '@encryption/src/crypto/vault-manifest';
import { activeIdentity, identityPublicKeyWire } from '@encryption/src/crypto/vault-state';
import { DEFAULT_KDF_PARAMS, deriveKek, deriveVaultAuthKeyPair, unwrapVrk, verifyAuthPublicKeyBinding } from '@encryption/src/crypto/vault-unlock';
import { BROADCAST_CHANNEL_NAME, BROADCAST_KEYS_CHANGED } from '@encryption/src/shared/constants';
import { closeVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { handleCommitStagedVault, handleUncommitStagedVault } from '@encryption/src/vault/operations/commit-staged';
import { handleGenerateKeys } from '@encryption/src/vault/operations/generate-keys';
import { handleHasKeys } from '@encryption/src/vault/operations/key-management';
import { handleChangeRecoveryPhrase, handlePrepareOnboarding } from '@encryption/src/vault/operations/onboarding';
import { handleRestoreFromPhrase } from '@encryption/src/vault/operations/vault-restore';
import { clearVaultCache, getVaultCache } from '@encryption/src/vault/vault-cache';
import { loadVault } from '@encryption/src/vault/vault-keys';

beforeAll(async () => {
  await sodium.ready;
});

afterAll(() => {
  closeVaultBroadcastChannel();
});

describe('onboarding bundle builder', () => {
  // The vault keeps its identity key raw; everything compared with the server
  // (fingerprints, councils, escrow audits) must go through the wire form it registered.
  it('stores the identity key it registers, in the form identityPublicKeyWire turns back into the registered one', async () => {
    const registered = await handleGenerateKeys('u-wire');
    const identity = activeIdentity((await loadVault('u-wire'))!.state)!;

    expect(base64ToUint8(identity.signaturePublicKey)).toHaveLength(32);
    expect(identityPublicKeyWire(identity)).toBe(registered.signaturePublicKey);
  });

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

describe('other tabs', () => {
  // Another tab's vault: its own channel instance receives what this one posts.
  async function listen<T>(run: () => Promise<T>): Promise<string[]> {
    const other = new BroadcastChannel(BROADCAST_CHANNEL_NAME);
    const received: string[] = [];
    other.onmessage = (event: MessageEvent<{ type: string }>) => received.push(event.data.type);

    await run();
    await new Promise((resolve) => setTimeout(resolve, 50));
    other.close();

    return received;
  }

  it('are told of new keys once has-keys sees them, not while the onboarding is staged', async () => {
    const userId = 'u-tabs';

    // Told now, a product would ask, hear "no keys" and never be told again.
    expect(await listen(() => handleGenerateKeys(userId))).toEqual([]);
    expect(await handleHasKeys(userId)).toEqual({ hasKeys: false });

    expect(await listen(() => handleCommitStagedVault(userId))).toEqual([BROADCAST_KEYS_CHANGED]);
    expect(await handleHasKeys(userId)).toEqual({ hasKeys: true });

    // A failed registration takes them back, and says so.
    expect(await listen(() => handleUncommitStagedVault(userId))).toEqual([BROADCAST_KEYS_CHANGED]);
    expect(await handleHasKeys(userId)).toEqual({ hasKeys: false });

    // Nothing staged: nothing committed, nothing announced.
    expect(await listen(() => handleCommitStagedVault('u-nothing-staged'))).toEqual([]);
  });
});

describe('restore through a handed-over phrase', () => {
  // The server's answers for a vault minted here, as /api/vault/fetch returns it.
  async function serving(userId: string, credentialType: 'primary' | 'council') {
    await handleGenerateKeys(userId);
    const { recoveryPhrase, keyring } = await handlePrepareOnboarding(userId, { lang: 'english' });
    const entry = (await getVaultCache(userId))!;
    await clearVaultCache(userId);

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
        if (url.endsWith('/api/vault/meta')) return json({ kdf_variants: [{ kdf_ops: keyring.kdf_ops, kdf_mem: keyring.kdf_mem }] });
        if (url.endsWith('/api/vault/challenge')) return json({ challenge_id: 'c', nonce: uint8ToBase64(new Uint8Array(32)) });

        return json({
          is_active: true,
          credential_type: credentialType,
          created_at_millis: 1,
          wrapped_vrk: keyring.wrapped_vrk,
          items: entry.sealed.map((i) => ({ item_id: i.id, type: i.type, revision_date_millis: i.revisionDate, ciphertext: i.ciphertext })),
          manifest: entry.manifest,
          manifest_sig: entry.manifestSig,
          revision: entry.revision,
        });
      })
    );

    return recoveryPhrase;
  }

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('keeps the vault in memory until the phrase change commits it', async () => {
    const userId = 'u-council-unlock';
    const recoveryPhrase = await serving(userId, 'council');

    await handleRestoreFromPhrase(userId, { recoveryPhrase, idToken: 't' });
    expect(await handleHasKeys(userId)).toEqual({ hasKeys: false });
    expect(await getVaultCache(userId)).not.toBeNull();

    await handleCommitStagedVault(userId);
    expect(await handleHasKeys(userId)).toEqual({ hasKeys: true });
  });

  it('keeps the vault on this device at once with the user’s own phrase', async () => {
    const userId = 'u-own-phrase';
    const recoveryPhrase = await serving(userId, 'primary');

    await handleRestoreFromPhrase(userId, { recoveryPhrase, idToken: 't' });
    expect(await handleHasKeys(userId)).toEqual({ hasKeys: true });
  });
});
