import { encodePopChallengeMessage, hybridDecapsulate, signDetached } from '@encryption/src/crypto';
import { base64ToUint8, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { computeChallengeResponse } from '@encryption/src/crypto/key-possession-challenge';
import { getStoredKeyBundle } from '@encryption/src/vault/operations/key-management';

/**
 * Vault side of the proof-of-possession flow. Proves possession of BOTH
 * private keys in a single round trip:
 *
 *   - Encryption key: decapsulate the server's X-Wing challenge ciphertext and
 *     return HMAC(sharedSecret, challengeId) — the existing KEM-based PoP.
 *   - Signature (identity) key: sign the server-issued `challengeId` (under a
 *     domain-separated message) with the Ed25519 secret key.
 *
 * Tying the signature to the server's fresh `challengeId` makes it a genuine
 * proof of possession of the identity key (not a replayable static signature),
 * complementing the registration binding signature.
 *
 * Neither secret key — nor anything reusable derived from them — crosses the
 * postMessage boundary; only the HMAC tag and the detached signature do.
 */
export async function handleRespondToKeyChallenge(
  userId: string,
  payload: { challengeId: string; ciphertext: string }
): Promise<{ response: string; challengeSignature: string }> {
  const bundle = await getStoredKeyBundle(userId);

  const ciphertext = base64ToUint8(payload.ciphertext);
  const sharedSecret = await hybridDecapsulate(bundle.encryption.secretKey, ciphertext);
  const responseBytes = await computeChallengeResponse(sharedSecret, payload.challengeId);

  const challengeMessage = encodePopChallengeMessage(payload.challengeId);
  const challengeSignature = await signDetached(challengeMessage, bundle.signature.secretKey);

  return {
    response: uint8ToBase64(responseBytes),
    challengeSignature: uint8ToBase64(challengeSignature),
  };
}
