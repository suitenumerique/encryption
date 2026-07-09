import { exportPublicKeyAsBase64, generateSignatureKeyPair, generateUserKeyPair } from '@encryption/src/crypto';
import { BROADCAST_KEYS_CHANGED } from '@encryption/src/shared/constants';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { serialized } from '@encryption/src/vault/operations/key-management';
import { clearSymmetricKeyCache } from '@encryption/src/vault/symmetric-key-cache';
import { createVault } from '@encryption/src/vault/vault-keys';

/**
 * Generate a fresh identity for the user: an encryption key pair (X-Wing) AND
 * a signature key pair (Ed25519, the identity). They are minted and stored
 * together as the first generation/version of a new synchronized vault — the
 * signature key fingerprint is what contacts verify, and it must never exist
 * without its bound encryption key (or vice versa).
 *
 * Returns both public keys (wire base64). `createVault` stages the vault in
 * memory (it is not registered yet, so has-keys stays false and abandoning the
 * flow leaves nothing behind); the caller persists it with commitStagedVault once
 * registration succeeds (see signKeyRegistration + the proof-of-possession flow).
 */
export async function handleGenerateKeys(userId: string): Promise<{ publicKey: string; signaturePublicKey: string }> {
  return serialized(async () => {
    const encryptionKeyPair = await generateUserKeyPair();
    const signatureKeyPair = await generateSignatureKeyPair();

    // A fresh onboarding is generation 1 / version 1; both match the server's
    // first-registration numbering, so the sealed items line up on bootstrap.
    await createVault(userId, { encryption: encryptionKeyPair, signature: signatureKeyPair });

    // New identity/vault: previously-cached symmetric keys were unwrapped by the
    // OLD keys, so they must not be reused (the cache is keyed by userId, which is
    // unchanged). Drop them so decryption goes through the new vault.
    clearSymmetricKeyCache();

    // Notify other tabs/iframes that keys changed
    getVaultBroadcastChannel()?.postMessage({ type: BROADCAST_KEYS_CHANGED });

    return {
      publicKey: exportPublicKeyAsBase64(encryptionKeyPair.publicKey),
      signaturePublicKey: exportPublicKeyAsBase64(signatureKeyPair.publicKey),
    };
  });
}
