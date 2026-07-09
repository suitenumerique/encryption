import sodium from 'libsodium-wrappers-sumo';

import { ensureSodium, generateUserKeyPair, hybridDecapsulate } from '@encryption/src/crypto/encryption';
import { computeChallengeResponse, createKeyPossessionChallenge, verifyChallengeResponse } from '@encryption/src/crypto/key-possession-challenge';

describe('key-possession-challenge', () => {
  it('roundtrips: holder of the secret key recovers the expected HMAC', async () => {
    await ensureSodium();
    const keyPair = await generateUserKeyPair();
    const challengeId = '11111111-1111-4111-8111-111111111111';

    const { ciphertext, expectedHmac } = await createKeyPossessionChallenge(keyPair.publicKey, challengeId);

    expect(ciphertext.length).toBe(sodium.crypto_kem_xwing_CIPHERTEXTBYTES);
    expect(expectedHmac.length).toBe(32);

    // Client side: decapsulate with sk and recompute the response
    const ss = await hybridDecapsulate(keyPair.secretKey, ciphertext);
    const response = await computeChallengeResponse(ss, challengeId);

    expect(await verifyChallengeResponse(expectedHmac, response)).toBe(true);
  });

  it('rejects a response computed with a different secret key', async () => {
    const keyPairA = await generateUserKeyPair();
    const keyPairB = await generateUserKeyPair();
    const challengeId = '22222222-2222-4222-8222-222222222222';

    const { ciphertext, expectedHmac } = await createKeyPossessionChallenge(keyPairA.publicKey, challengeId);

    // Wrong holder: ss derived from B's sk doesn't match A's challenge
    const wrongSs = await hybridDecapsulate(keyPairB.secretKey, ciphertext);
    const wrongResponse = await computeChallengeResponse(wrongSs, challengeId);

    expect(await verifyChallengeResponse(expectedHmac, wrongResponse)).toBe(false);
  });

  it('rejects a response bound to a different challenge id', async () => {
    const keyPair = await generateUserKeyPair();
    const challengeId = '33333333-3333-4333-8333-333333333333';
    const otherChallengeId = '44444444-4444-4444-8444-444444444444';

    const { ciphertext, expectedHmac } = await createKeyPossessionChallenge(keyPair.publicKey, challengeId);

    const ss = await hybridDecapsulate(keyPair.secretKey, ciphertext);
    // Right secret, wrong challenge id → HMAC differs
    const responseForWrongId = await computeChallengeResponse(ss, otherChallengeId);

    expect(await verifyChallengeResponse(expectedHmac, responseForWrongId)).toBe(false);
  });
});
