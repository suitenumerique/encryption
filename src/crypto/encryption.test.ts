/**
 * Tests for the libsodium-based encryption functions.
 * X-Wing hybrid KEM (X25519 + ML-KEM-768) + XChaCha20-Poly1305 symmetric encryption.
 */
import fc from 'fast-check';
import sodium from 'libsodium-wrappers-sumo';
import { describe, expect, it } from 'vitest';

import {
  decryptContent,
  decryptSymmetricKeyForUser,
  encryptContent,
  encryptSymmetricKeyForUsers,
  ensureSodium,
  generateSymmetricKey,
  generateUserKeyPair,
  hybridDecapsulate,
  hybridEncapsulate,
} from '@encryption/src/crypto/encryption';
import { CRYPTO_VERSION } from '@encryption/src/shared/constants';
import { VaultError } from '@encryption/src/shared/vault-error';

describe('encryption', () => {
  describe('generateUserKeyPair', () => {
    it('should generate an X-Wing key pair with sizes matching libsodium constants', async () => {
      await ensureSodium();
      const keyPair = await generateUserKeyPair();

      expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.secretKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.length).toBe(sodium.crypto_kem_xwing_PUBLICKEYBYTES);
      expect(keyPair.secretKey.length).toBe(sodium.crypto_kem_xwing_SECRETKEYBYTES);
    });

    it('should produce distinct key pairs across calls', async () => {
      const a = await generateUserKeyPair();
      const b = await generateUserKeyPair();

      expect(Buffer.from(a.publicKey).toString('hex')).not.toBe(Buffer.from(b.publicKey).toString('hex'));
      expect(Buffer.from(a.secretKey).toString('hex')).not.toBe(Buffer.from(b.secretKey).toString('hex'));
    });
  });

  describe('generateSymmetricKey', () => {
    it('should generate a 32-byte symmetric key', async () => {
      const key = await generateSymmetricKey();

      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(32); // XChaCha20-Poly1305 key size
    });
  });

  describe('encryptContent / decryptContent', () => {
    it('should roundtrip encrypt and decrypt content', async () => {
      const symmetricKey = await generateSymmetricKey();
      const plaintext = new TextEncoder().encode('Hello, encrypted world!');

      const encrypted = await encryptContent(plaintext, symmetricKey);

      expect(encrypted.length).toBeGreaterThan(plaintext.length);
      expect(encrypted[0]).toBe(CRYPTO_VERSION);

      const decrypted = await decryptContent(encrypted, symmetricKey);

      expect(new TextDecoder().decode(decrypted)).toBe('Hello, encrypted world!');
    });

    it('should produce different ciphertexts for the same input (random nonce)', async () => {
      const symmetricKey = await generateSymmetricKey();
      const plaintext = new TextEncoder().encode('same input');

      const encrypted1 = await encryptContent(plaintext, symmetricKey);
      const encrypted2 = await encryptContent(plaintext, symmetricKey);

      // Nonces are random, so ciphertexts differ
      expect(Buffer.from(encrypted1).toString('hex')).not.toBe(Buffer.from(encrypted2).toString('hex'));
    });

    it('should fail to decrypt with wrong key', async () => {
      const key1 = await generateSymmetricKey();
      const key2 = await generateSymmetricKey();
      const plaintext = new TextEncoder().encode('secret');

      const encrypted = await encryptContent(plaintext, key1);

      expect(() => decryptContent(encrypted, key2)).rejects.toThrow();
    });

    it('should reject blobs with an unknown version byte', async () => {
      const symmetricKey = await generateSymmetricKey();
      const plaintext = new TextEncoder().encode('versioned');

      const encrypted = await encryptContent(plaintext, symmetricKey);
      const tampered = new Uint8Array(encrypted);
      tampered[0] = 0xff;

      await expect(decryptContent(tampered, symmetricKey)).rejects.toThrow(/unsupported crypto version/i);
    });
  });

  describe('hybrid encapsulate / decapsulate', () => {
    it('should produce matching shared secrets', async () => {
      const keyPair = await generateUserKeyPair();

      const { sharedSecret: encSecret, ciphertext } = await hybridEncapsulate(keyPair.publicKey);
      const decSecret = await hybridDecapsulate(keyPair.secretKey, ciphertext);

      expect(encSecret).toEqual(decSecret);
      expect(encSecret.length).toBe(sodium.crypto_kem_xwing_SHAREDSECRETBYTES);
      expect(ciphertext.length).toBe(sodium.crypto_kem_xwing_CIPHERTEXTBYTES);
    });

    it('should diverge when decapsulating with the wrong secret key', async () => {
      const keyPair1 = await generateUserKeyPair();
      const keyPair2 = await generateUserKeyPair();

      const { ciphertext } = await hybridEncapsulate(keyPair1.publicKey);

      const wrongSecret = await hybridDecapsulate(keyPair2.secretKey, ciphertext);
      const rightSecret = await hybridDecapsulate(keyPair1.secretKey, ciphertext);

      expect(wrongSecret).not.toEqual(rightSecret);
    });
  });

  describe('multi-user symmetric key encryption', () => {
    it('should encrypt and decrypt a symmetric key for multiple users', async () => {
      const user1 = await generateUserKeyPair();
      const user2 = await generateUserKeyPair();
      const symmetricKey = await generateSymmetricKey();

      const encrypted = await encryptSymmetricKeyForUsers(symmetricKey, {
        user1: user1.publicKey,
        user2: user2.publicKey,
      });

      expect(encrypted['user1']).toBeInstanceOf(Uint8Array);
      expect(encrypted['user2']).toBeInstanceOf(Uint8Array);
      expect(encrypted['user1'][0]).toBe(CRYPTO_VERSION);

      const decrypted1 = await decryptSymmetricKeyForUser(user1.secretKey, encrypted['user1']);
      const decrypted2 = await decryptSymmetricKeyForUser(user2.secretKey, encrypted['user2']);

      expect(decrypted1).toEqual(symmetricKey);
      expect(decrypted2).toEqual(symmetricKey);
    });

    it('should reject wraps with an unknown version byte', async () => {
      const user = await generateUserKeyPair();
      const symmetricKey = await generateSymmetricKey();

      const wraps = await encryptSymmetricKeyForUsers(symmetricKey, { user: user.publicKey });
      const tampered = new Uint8Array(wraps['user']);
      tampered[0] = 0xff;

      await expect(decryptSymmetricKeyForUser(user.secretKey, tampered)).rejects.toThrow(/unsupported crypto version/i);
    });
  });
});

describe('decryption over arbitrary input (property)', () => {
  const flipBit = (bytes: Uint8Array, bit: number): Uint8Array => {
    const out = new Uint8Array(bytes);
    out[bit >> 3] ^= 1 << (bit & 7);

    return out;
  };

  it('decryptContent round-trips any content and rejects any bit flip with a VaultError', async () => {
    const key = await generateSymmetricKey();

    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 512 }), fc.nat(), async (content, seed) => {
        const encrypted = await encryptContent(content, key);
        expect(await decryptContent(encrypted, key)).toEqual(content);

        const flipped = flipBit(encrypted, seed % (encrypted.length * 8));
        await expect(decryptContent(flipped, key)).rejects.toBeInstanceOf(VaultError);
      }),
      { numRuns: 100 }
    );
  });

  it('decryptContent rejects random bytes with a VaultError', async () => {
    const key = await generateSymmetricKey();

    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 256 }), async (bytes) => {
        await expect(decryptContent(bytes, key)).rejects.toBeInstanceOf(VaultError);
      }),
      { numRuns: 200 }
    );
  });

  it('decryptSymmetricKeyForUser round-trips and rejects any bit flip with a VaultError', async () => {
    const recipient = await generateUserKeyPair();
    const symmetricKey = await generateSymmetricKey();
    const { alice: wrapped } = await encryptSymmetricKeyForUsers(symmetricKey, { alice: recipient.publicKey });

    expect(await decryptSymmetricKeyForUser(recipient.secretKey, wrapped)).toEqual(symmetricKey);

    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 0, max: wrapped.length * 8 - 1 }), async (bit) => {
        await expect(decryptSymmetricKeyForUser(recipient.secretKey, flipBit(wrapped, bit))).rejects.toBeInstanceOf(VaultError);
      }),
      { numRuns: 100 }
    );
  });

  it('decryptSymmetricKeyForUser rejects random bytes with a VaultError', async () => {
    const recipient = await generateUserKeyPair();
    // Bias towards a plausible header so the length field itself gets fuzzed.
    const blob = fc.oneof(
      fc.uint8Array({ maxLength: 1300 }),
      fc
        .tuple(fc.integer({ min: 0, max: 0xffff }), fc.uint8Array({ maxLength: 1300 }))
        .map(([len, rest]) => new Uint8Array([CRYPTO_VERSION, len & 0xff, len >> 8, ...rest]))
    );

    await fc.assert(
      fc.asyncProperty(blob, async (bytes) => {
        await expect(decryptSymmetricKeyForUser(recipient.secretKey, bytes)).rejects.toBeInstanceOf(VaultError);
      }),
      { numRuns: 200 }
    );
  });
});
