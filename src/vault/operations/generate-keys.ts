import { exportPublicKeyAsBase64, generateSignatureKeyPair, generateUserKeyPair, getEncryptionDB } from '@encryption/src/crypto';
import { BROADCAST_KEYS_CHANGED, STORE_KEY_PAIRS } from '@encryption/src/shared/constants';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { serialized } from '@encryption/src/vault/operations/key-management';

/**
 * Generate a fresh identity for the user: an encryption key pair (X-Wing) AND
 * a signature key pair (Ed25519, the identity). They are minted and stored
 * together so a device always holds a complete, self-consistent identity —
 * the signature key fingerprint is what contacts verify, and it must never
 * exist without its bound encryption key (or vice versa).
 *
 * Returns both public keys (wire base64). Registration with the server is a
 * separate step (see signKeyRegistration + the proof-of-possession flow).
 */
export async function handleGenerateKeys(userId: string): Promise<{ publicKey: string; signaturePublicKey: string }> {
  return serialized(async () => {
    const encryptionKeyPair = await generateUserKeyPair();
    const signatureKeyPair = await generateSignatureKeyPair();
    const db = await getEncryptionDB();

    await db.put(
      STORE_KEY_PAIRS,
      {
        publicKey: encryptionKeyPair.publicKey,
        secretKey: encryptionKeyPair.secretKey,
        signaturePublicKey: signatureKeyPair.publicKey,
        signatureSecretKey: signatureKeyPair.secretKey,
      },
      userId
    );

    // Notify other tabs/iframes that keys changed
    getVaultBroadcastChannel()?.postMessage({ type: BROADCAST_KEYS_CHANGED });

    return {
      publicKey: exportPublicKeyAsBase64(encryptionKeyPair.publicKey),
      signaturePublicKey: exportPublicKeyAsBase64(signatureKeyPair.publicKey),
    };
  });
}
