import { hybridDecapsulate } from '@encryption/src/crypto/encryption';
import { base64ToUint8, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { computeChallengeResponse } from '@encryption/src/crypto/key-possession-challenge';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { getStoredKeyPair } from '@encryption/src/vault/operations/key-management';

/**
 * Vault side of the proof-of-possession flow. Reads the secret key written
 * by `handleGenerateKeys`, decapsulates the server's challenge ciphertext
 * with it, and returns the HMAC tag the server expects.
 *
 * The shared secret never crosses the postMessage boundary — only the tag
 * does. This keeps the same isolation property as every other vault op:
 * the iframe is the only place the private key (or anything derived from
 * it that's reusable) is ever materialised.
 */
export async function handleRespondToKeyChallenge(
  userId: string,
  payload: { challengeId: string; ciphertext: string },
): Promise<{ response: string }> {
  const pair = await getStoredKeyPair(userId);

  if (!pair) {
    throw new VaultError(VaultErrorCode.MISSING_KEYS, 'No key pair found. Generate keys first.');
  }

  const ciphertext = base64ToUint8(payload.ciphertext);
  const sharedSecret = await hybridDecapsulate(pair.secretKey, ciphertext);
  const responseBytes = await computeChallengeResponse(sharedSecret, payload.challengeId);

  return { response: uint8ToBase64(responseBytes) };
}
