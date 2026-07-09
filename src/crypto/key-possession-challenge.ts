/**
 * Proof-of-Possession (PoP) challenge for X-Wing public-key registration.
 *
 * Used at `/api/keys/init` + `/api/keys/complete` to make sure the user
 * actually holds the private key they're trying to register, before the
 * server persists the public key for the user. Without this, an authorised
 * caller (with a valid OIDC JWT) could register a public key whose
 * private counterpart they cannot decrypt with — either by accident
 * (frontend bug) or to claim someone else's published pubkey as their own.
 *
 * Protocol summary (server's first three steps live in this file, the
 * client's response computation is the same `computeChallengeResponse`
 * function called from inside the vault):
 *
 *   1. Client → Server : POST /api/keys/init { public_key }
 *   2. Server          : (ct, ss) = crypto_kem_xwing_enc(pk)
 *                        expected = HMAC_SHA256(key=ss, msg=id)
 *                        store (id, expected, pk, expiresAt) ; reply (id, ct)
 *   3. Client (vault)  : ss' = crypto_kem_xwing_dec(ct, sk)
 *                        response = HMAC_SHA256(ss', id)
 *   4. Client → Server : POST /api/keys/complete { id, response }
 *   5. Server          : constant-time compare(response, expected) ; commit
 *
 * `ss` is single-use, dropped from memory after step 2. The server only
 * keeps `expected` (32 bytes), so a DB dump leaks neither the private key
 * nor the encapsulated secret.
 */
import sodium from 'libsodium-wrappers-sumo';

import { type HybridPublicKey, ensureSodium, hybridEncapsulate } from '@encryption/src/crypto/encryption';

/**
 * Server-side: produce the X-Wing ciphertext to send to the client and the
 * expected HMAC tag the client must echo back.
 *
 * `challengeId` should be a freshly generated identifier (UUID v4 from the
 * DB row is fine) — it doubles as the HMAC message so each challenge has
 * its own response, blocking cross-challenge replay.
 */
export async function createKeyPossessionChallenge(
  publicKey: HybridPublicKey,
  challengeId: string
): Promise<{ ciphertext: Uint8Array; expectedHmac: Uint8Array }> {
  await ensureSodium();

  const { sharedSecret, ciphertext } = await hybridEncapsulate(publicKey);
  const expectedHmac = await computeChallengeResponse(sharedSecret, challengeId);

  return { ciphertext, expectedHmac };
}

/**
 * Both sides: derive the response tag from the shared secret and challenge id.
 * HMAC binds the tag to `challengeId` so a captured response can't be replayed
 * against a different challenge.
 */
export async function computeChallengeResponse(sharedSecret: Uint8Array, challengeId: string): Promise<Uint8Array> {
  await ensureSodium();

  // crypto_auth_hmacsha256 takes (message, key) and returns a 32-byte tag.
  return sodium.crypto_auth_hmacsha256(sodium.from_string(challengeId), sharedSecret);
}

/**
 * Server-side: constant-time comparison of expected vs received HMAC tags.
 * Wrap libsodium's `memcmp` so callers don't have to think about sodium
 * readiness or operand lengths.
 */
export async function verifyChallengeResponse(expected: Uint8Array, received: Uint8Array): Promise<boolean> {
  await ensureSodium();

  if (expected.length !== received.length) {
    return false;
  }

  return sodium.memcmp(expected, received);
}
