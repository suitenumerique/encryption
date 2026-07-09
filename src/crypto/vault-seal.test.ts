import sodium from 'libsodium-wrappers-sumo';

import { generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import type { PlainItem } from '@encryption/src/crypto/vault-items';
import { buildSignedManifest, openState, sealItem, sealState, verifyPulledVault } from '@encryption/src/crypto/vault-seal';
import { addEncryptionKey, addIdentity, emptyVaultState, mergeVaultState, setTofu } from '@encryption/src/crypto/vault-state';

function sampleState() {
  let s = emptyVaultState();
  s = addIdentity(s, { generation: 1, algo: 'ed25519', signaturePublicKey: 'sp', signatureSecretKey: 'ss', createdAt: 10 });
  s = addEncryptionKey(s, { version: 1, algo: 'x-wing', publicKey: 'p1', secretKey: 's1', createdAt: 10 });
  s = setTofu(s, 'bob', 'fp-bob', 'trusted', 20);

  return mergeVaultState(s, emptyVaultState());
}

beforeAll(async () => {
  await sodium.ready;
});

describe('seal / open round trip', () => {
  it('recovers the exact state through the VRK', async () => {
    const vrk = sodium.randombytes_buf(32);
    const state = sampleState();

    expect(await openState(await sealState(state, vrk), vrk)).toEqual(state);
  });

  it('rejects a decrypted payload that does not match its declared type', async () => {
    const vrk = sodium.randombytes_buf(32);
    // Authentic (correctly sealed under the VRK) but the payload is missing the
    // fields an "identity" item requires: the schema must catch it, not let an
    // undefined field propagate into VaultState.
    const bad = await sealItem({ id: 'identity:1', type: 'identity', revisionDate: 10, payload: { generation: 1 } } as unknown as PlainItem, vrk);

    await expect(openState([bad], vrk)).rejects.toThrow();
  });
});

describe('verifyPulledVault', () => {
  it('accepts a well-formed, signed, fully-covered pull', async () => {
    const vrk = sodium.randombytes_buf(32);
    const identity = await generateSignatureKeyPair();
    const sealed = await sealState(sampleState(), vrk);
    const { manifest, manifestSig } = await buildSignedManifest(5, 1, sealed, identity.secretKey);

    expect(await verifyPulledVault(sealed, manifest, manifestSig, identity.publicKey, 5)).toBe(true);
  });

  it('rejects a rollback, a wrong signer, and a tampered item', async () => {
    const vrk = sodium.randombytes_buf(32);
    const identity = await generateSignatureKeyPair();
    const attacker = await generateSignatureKeyPair();
    const sealed = await sealState(sampleState(), vrk);
    const { manifest, manifestSig } = await buildSignedManifest(5, 1, sealed, identity.secretKey);

    // rollback: last seen 6 > pulled 5
    expect(await verifyPulledVault(sealed, manifest, manifestSig, identity.publicKey, 6)).toBe(false);

    // wrong signer
    const forged = await buildSignedManifest(5, 1, sealed, attacker.secretKey);
    expect(await verifyPulledVault(sealed, forged.manifest, forged.manifestSig, identity.publicKey, 5)).toBe(false);

    // tampered ciphertext not covered by the signed manifest
    const tampered = sealed.map((s, i) => (i === 0 ? { ...s, ciphertext: s.ciphertext.slice(0, -4) + 'AAAA' } : s));
    expect(await verifyPulledVault(tampered, manifest, manifestSig, identity.publicKey, 5)).toBe(false);
  });
});
