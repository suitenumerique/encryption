import sodium from 'libsodium-wrappers-sumo';

import { assertValidSignaturePublicKey, generateSignatureKeyPair, signDetached, verifyDetached } from '@encryption/src/crypto/signature';

describe('signature (Ed25519)', () => {
  it('should generate a key pair with libsodium-sized keys', async () => {
    const kp = await generateSignatureKeyPair();

    expect(kp.publicKey.length).toBe(sodium.crypto_sign_PUBLICKEYBYTES);
    expect(kp.secretKey.length).toBe(sodium.crypto_sign_SECRETKEYBYTES);
  });

  it('should sign and verify a message', async () => {
    const kp = await generateSignatureKeyPair();
    const message = new TextEncoder().encode('the identity speaks');

    const signature = await signDetached(message, kp.secretKey);
    expect(signature.length).toBe(sodium.crypto_sign_BYTES);

    expect(await verifyDetached(signature, message, kp.publicKey)).toBe(true);
  });

  it('should reject a tampered message', async () => {
    const kp = await generateSignatureKeyPair();
    const message = new TextEncoder().encode('original');
    const signature = await signDetached(message, kp.secretKey);

    const tampered = new TextEncoder().encode('originai');
    expect(await verifyDetached(signature, tampered, kp.publicKey)).toBe(false);
  });

  it('should reject a signature from a different key', async () => {
    const a = await generateSignatureKeyPair();
    const b = await generateSignatureKeyPair();
    const message = new TextEncoder().encode('whose key signed this?');

    const signature = await signDetached(message, a.secretKey);
    expect(await verifyDetached(signature, message, b.publicKey)).toBe(false);
  });

  it('should return false (not throw) for malformed inputs', async () => {
    const kp = await generateSignatureKeyPair();
    const message = new TextEncoder().encode('x');
    const signature = await signDetached(message, kp.secretKey);

    // Wrong-length public key and wrong-length signature both fail safely.
    expect(await verifyDetached(signature, message, new Uint8Array(10))).toBe(false);
    expect(await verifyDetached(new Uint8Array(10), message, kp.publicKey)).toBe(false);
  });

  it('assertValidSignaturePublicKey accepts a real key and rejects a malformed one', async () => {
    const kp = await generateSignatureKeyPair();

    await expect(assertValidSignaturePublicKey(kp.publicKey)).resolves.toBeUndefined();
    await expect(assertValidSignaturePublicKey(new Uint8Array(31))).rejects.toThrow(/signature public key/i);
  });
});
