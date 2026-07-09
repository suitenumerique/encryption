import 'fake-indexeddb/auto';
import sodium from 'libsodium-wrappers-sumo';

import { generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { exportPublicKeyAsBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import { activeEncryptionKey, activeIdentity } from '@encryption/src/crypto/vault-state';
import { VaultErrorCode } from '@encryption/src/shared/vault-error';
import { closeVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { handleCommitStagedVault, handleUncommitStagedVault } from '@encryption/src/vault/operations/commit-staged';
import { handleDestroyKeys } from '@encryption/src/vault/operations/destroy-keys';
import {
  handleAcceptFingerprint,
  handleCheckFingerprints,
  handleGetKnownFingerprints,
  handleRefuseFingerprint,
} from '@encryption/src/vault/operations/fingerprint-registry';
import { handleGenerateKeys } from '@encryption/src/vault/operations/generate-keys';
import { getStoredKeyBundle, getStoredKeyPair, handleHasKeys } from '@encryption/src/vault/operations/key-management';
import { createVault, deriveStoredKeyPair, loadVault } from '@encryption/src/vault/vault-keys';

// Accept/refuse fingerprint are write-through (they push via the sync engine).
// Unit tests have no server, so stand in a `handleSync` that just applies the
// write-through mutation locally (as a successful push would) and reports ok.
jest.mock('@encryption/src/vault/operations/vault-sync-run', () => {
  const actual = jest.requireActual('@encryption/src/vault/vault-keys');

  return {
    handleSync: async (userId: string, payload?: { mutate?: (s: unknown) => unknown }) => {
      if (payload?.mutate) await actual.mutateVault(userId, payload.mutate);

      return { status: 'ok', revision: 0 };
    },
  };
});

beforeAll(async () => {
  await sodium.ready;
});

// generate/import broadcast on a shared BroadcastChannel; close it so the open
// handle doesn't keep jest alive.
afterAll(() => {
  closeVaultBroadcastChannel();
});

async function freshBundle() {
  return { encryption: await generateUserKeyPair(), signature: await generateSignatureKeyPair() };
}

describe('vault-keys seam (VaultState-backed key store)', () => {
  it('generates a vault and reads the identity back through the same StoredKeyPair contract', async () => {
    const userId = 'u-generate';

    const res = await handleGenerateKeys(userId);

    // generate-keys only stages: not on disk until committed.
    expect((await handleHasKeys(userId)).hasKeys).toBe(false);
    await handleCommitStagedVault(userId);
    expect((await handleHasKeys(userId)).hasKeys).toBe(true);

    // The public key returned to the UI is the one now derivable from the vault.
    const bundle = await getStoredKeyBundle(userId);
    expect(exportPublicKeyAsBase64(bundle.encryption.publicKey)).toBe(res.publicKey);
    expect(exportPublicKeyAsBase64(bundle.signature.publicKey)).toBe(res.signaturePublicKey);

    // A fresh onboarding is generation 1 / version 1.
    const loaded = await loadVault(userId);
    expect(activeEncryptionKey(loaded!.state)?.version).toBe(1);
    expect(activeIdentity(loaded!.state)?.generation).toBe(1);
  });

  it('round-trips the exact key bytes through seal -> device-wrapped cache -> open', async () => {
    const userId = 'u-roundtrip';
    const bundle = await freshBundle();

    await createVault(userId, bundle);
    const pair = deriveStoredKeyPair((await loadVault(userId))!.state);

    expect(uint8ToBase64(pair!.publicKey)).toBe(uint8ToBase64(bundle.encryption.publicKey));
    expect(uint8ToBase64(pair!.secretKey)).toBe(uint8ToBase64(bundle.encryption.secretKey));
    expect(uint8ToBase64(pair!.signatureSecretKey!)).toBe(uint8ToBase64(bundle.signature.secretKey));
  });

  it('reports no keys and no stored pair when the device has no vault', async () => {
    expect((await handleHasKeys('u-empty')).hasKeys).toBe(false);
    expect(await getStoredKeyPair('u-empty')).toBeNull();
  });

  it('a staged onboarding vault stays off disk (has-keys false) until committed', async () => {
    const userId = 'u-staged';

    // Onboarding mints the vault in memory only.
    await handleGenerateKeys(userId);

    // Nothing is on disk yet: has-keys reports false so a product never treats an
    // un-registered user as ready...
    expect((await handleHasKeys(userId)).hasKeys).toBe(false);
    // ...but the onboarding ops can still read the staged vault (e.g. to build the
    // recovery-kit bundle and sign the registration).
    const bundle = await getStoredKeyBundle(userId);
    expect(bundle.encryption.publicKey).toBeDefined();

    // Committing (before the server sync) writes it to disk.
    await handleCommitStagedVault(userId);
    expect((await handleHasKeys(userId)).hasKeys).toBe(true);
  });

  it('uncommit rolls a committed vault back to staging (has-keys false), and it can be re-committed', async () => {
    const userId = 'u-uncommit';

    await handleGenerateKeys(userId);
    await handleCommitStagedVault(userId);
    expect((await handleHasKeys(userId)).hasKeys).toBe(true);

    // A failed server sync uncommits: off disk (has-keys false), still in memory.
    await handleUncommitStagedVault(userId);
    expect((await handleHasKeys(userId)).hasKeys).toBe(false);

    // Retrying re-commits the same vault without regenerating anything.
    await handleCommitStagedVault(userId);
    expect((await handleHasKeys(userId)).hasKeys).toBe(true);
  });

  it('an abandoned staged onboarding leaves nothing on disk', async () => {
    const userId = 'u-staged-abandoned';

    await handleGenerateKeys(userId);
    // Cancelling (or a reload dropping memory) must leave no residue.
    await handleDestroyKeys(userId);

    expect((await handleHasKeys(userId)).hasKeys).toBe(false);
    expect(await getStoredKeyPair(userId)).toBeNull();
  });

  it('does not leak the VRK: a copied cache row is inert without the live device key', async () => {
    const userId = 'u-inert';
    await createVault(userId, await freshBundle());

    const loaded = await loadVault(userId);
    // The device key is non-extractable; proving that here guards the whole model.
    await expect(crypto.subtle.exportKey('raw', loaded!.cache.deviceKey)).rejects.toThrow();
  });
});

describe('fingerprint registry on VaultState.tofu', () => {
  it('reads a first encounter as unknown, trusts only after an explicit accept, and flags a later change as mismatch', async () => {
    const userId = 'u-tofu';
    await handleGenerateKeys(userId);

    // First encounter on a read-only check: unknown (seen, not verified), and
    // never auto-trusted. (A read does not record; only a share would.)
    const first = await handleCheckFingerprints(userId, { userFingerprints: { bob: 'fp-bob' } });
    expect(first.results[0]).toMatchObject({ userId: 'bob', knownFingerprint: null, status: 'unknown' });

    // Trust comes only from an explicit user decision.
    await handleAcceptFingerprint(userId, { userId: 'bob', fingerprint: 'fp-bob' });

    const again = await handleCheckFingerprints(userId, { userFingerprints: { bob: 'fp-bob' } });
    expect(again.results[0]).toMatchObject({ knownFingerprint: 'fp-bob', status: 'trusted' });

    // A DIFFERENT fingerprint for a known contact -> mismatch (needs a decision).
    const changed = await handleCheckFingerprints(userId, { userFingerprints: { bob: 'fp-evil' } });
    expect(changed.results[0].status).toBe('mismatch');
  });

  it('accept / refuse update the synced map and getKnownFingerprints reflects it', async () => {
    const userId = 'u-tofu2';
    await handleGenerateKeys(userId);

    await handleAcceptFingerprint(userId, { userId: 'carol', fingerprint: 'fp-carol' });
    await handleRefuseFingerprint(userId, { userId: 'dave', fingerprint: 'fp-dave' });

    const { fingerprints } = await handleGetKnownFingerprints(userId);
    expect(fingerprints.carol).toEqual({ fingerprint: 'fp-carol', status: 'trusted' });
    expect(fingerprints.dave).toEqual({ fingerprint: 'fp-dave', status: 'refused' });
  });

  it('throws NOT_INITIALIZED when there is no vault (a product should not be checking yet)', async () => {
    // Without a vault there is no trust state to consult and nothing can be shared
    // anyway, so checking fingerprints is meaningless. It fails loudly ("set up
    // encryption first") rather than pretending to answer "unknown".
    await expect(handleCheckFingerprints('u-no-vault', { userFingerprints: { bob: 'fp' } })).rejects.toMatchObject({
      code: VaultErrorCode.NOT_INITIALIZED,
    });
  });

  it('sticky refusal: a refused contact stays refused even when their fingerprint changes', async () => {
    const userId = 'u-sticky';
    await handleGenerateKeys(userId);

    await handleRefuseFingerprint(userId, { userId: 'mallory', fingerprint: 'fp-old' });

    // A rotated key (different fingerprint, no continuity chain) must NOT downgrade
    // to a neutral 'mismatch' that lets the user re-trust: it stays 'refused'.
    const changed = await handleCheckFingerprints(userId, { userFingerprints: { mallory: 'fp-new' } });
    expect(changed.results[0].status).toBe('refused');
  });
});
