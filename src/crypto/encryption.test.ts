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
import { DOMAIN_CONTENT, DOMAIN_KEM_DOCUMENT_KEY, DOMAIN_VAULT_ITEM } from '@encryption/src/shared/crypto-domains';
import { VaultError } from '@encryption/src/shared/vault-error';

const AD = DOMAIN_CONTENT;
const KEM_AD = DOMAIN_KEM_DOCUMENT_KEY;

const seq = (length: number, start = 0) => Uint8Array.from({ length }, (_, i) => (start + i) & 0xff);
const fromHex = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'));

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

      const encrypted = await encryptContent(plaintext, symmetricKey, AD);

      expect(encrypted.length).toBeGreaterThan(plaintext.length);
      expect(encrypted[0]).toBe(CRYPTO_VERSION);

      const decrypted = await decryptContent(encrypted, symmetricKey, AD);

      expect(new TextDecoder().decode(decrypted)).toBe('Hello, encrypted world!');
    });

    it('should produce different ciphertexts for the same input (random nonce)', async () => {
      const symmetricKey = await generateSymmetricKey();
      const plaintext = new TextEncoder().encode('same input');

      const encrypted1 = await encryptContent(plaintext, symmetricKey, AD);
      const encrypted2 = await encryptContent(plaintext, symmetricKey, AD);

      // Nonces are random, so ciphertexts differ
      expect(Buffer.from(encrypted1).toString('hex')).not.toBe(Buffer.from(encrypted2).toString('hex'));
    });

    it('should fail to decrypt with wrong key', async () => {
      const key1 = await generateSymmetricKey();
      const key2 = await generateSymmetricKey();
      const plaintext = new TextEncoder().encode('secret');

      const encrypted = await encryptContent(plaintext, key1, AD);

      await expect(decryptContent(encrypted, key2, AD)).rejects.toThrow();
    });

    it('should refuse to open a ciphertext as something it was not sealed as', async () => {
      const key = await generateSymmetricKey();
      const encrypted = await encryptContent(new TextEncoder().encode('a wrapped key'), key, 'lasuite-encryption/wrapped-key/v1');

      await expect(decryptContent(encrypted, key, 'lasuite-encryption/content/v1')).rejects.toBeInstanceOf(VaultError);
    });

    it('should refuse a ciphertext bound to another context', async () => {
      const key = await generateSymmetricKey();
      const encrypted = await encryptContent(new TextEncoder().encode('{}'), key, DOMAIN_VAULT_ITEM, [Buffer.from('a'), Buffer.from('bc')]);

      await expect(decryptContent(encrypted, key, DOMAIN_VAULT_ITEM, [Buffer.from('ab'), Buffer.from('c')])).rejects.toBeInstanceOf(VaultError);
      await expect(decryptContent(encrypted, key, DOMAIN_VAULT_ITEM)).rejects.toBeInstanceOf(VaultError);
    });

    // Fixed ciphertexts: they only open while the associated data (version byte,
    // label, framing of the context) stays byte-for-byte what it was.
    it('opens known-answer ciphertexts', async () => {
      expect(
        new TextDecoder().decode(
          await decryptContent(
            fromHex('017af70a459e9dbe90264aa49f91d7f07dc511528b9db745b2a48b0889186fcf4834cc378578ade8ffa032475c922f84'),
            seq(32),
            DOMAIN_CONTENT
          )
        )
      ).toBe('lasuite');
      expect(
        new TextDecoder().decode(
          await decryptContent(
            fromHex('01acc26af3938dcd347ab25209e82022471bf9bd68e278d0b3b25f546419029d631b379ac37b68b8b250c4'),
            seq(32),
            DOMAIN_VAULT_ITEM,
            [Buffer.from('tofu:bob'), Buffer.from('tofu')]
          )
        )
      ).toBe('{}');
    });

    it('should reject blobs with an unknown version byte', async () => {
      const symmetricKey = await generateSymmetricKey();
      const plaintext = new TextEncoder().encode('versioned');

      const encrypted = await encryptContent(plaintext, symmetricKey, AD);
      const tampered = new Uint8Array(encrypted);
      tampered[0] = 0xff;

      await expect(decryptContent(tampered, symmetricKey, AD)).rejects.toThrow(/unsupported crypto version/i);
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

      const encrypted = await encryptSymmetricKeyForUsers(
        symmetricKey,
        {
          user1: user1.publicKey,
          user2: user2.publicKey,
        },
        KEM_AD
      );

      expect(encrypted['user1']).toBeInstanceOf(Uint8Array);
      expect(encrypted['user2']).toBeInstanceOf(Uint8Array);
      expect(encrypted['user1'][0]).toBe(CRYPTO_VERSION);

      const decrypted1 = await decryptSymmetricKeyForUser(user1.secretKey, encrypted['user1'], KEM_AD);
      const decrypted2 = await decryptSymmetricKeyForUser(user2.secretKey, encrypted['user2'], KEM_AD);

      expect(decrypted1).toEqual(symmetricKey);
      expect(decrypted2).toEqual(symmetricKey);
    });

    it('should reject wraps with an unknown version byte', async () => {
      const user = await generateUserKeyPair();
      const symmetricKey = await generateSymmetricKey();

      const wraps = await encryptSymmetricKeyForUsers(symmetricKey, { user: user.publicKey }, KEM_AD);
      const tampered = new Uint8Array(wraps['user']);
      tampered[0] = 0xff;

      await expect(decryptSymmetricKeyForUser(user.secretKey, tampered, KEM_AD)).rejects.toThrow(/unsupported crypto version/i);
    });

    // A fixed wrap to a seeded key pair: it only opens while the derivation of
    // the wrapping key from the X-Wing secret and the label stay unchanged.
    it('opens a known-answer wrap', async () => {
      await ensureSodium();
      const recipient = sodium.crypto_kem_xwing_seed_keypair(seq(32));
      const wrapped = Uint8Array.from(
        Buffer.from(
          'AWAEDOYiJ3bYeUl/cA5kT53l+HuaDf/R4Fdb3+EoqhbuNFxK2AIKaWbVDfd2Id3mh9/Sh/+lTIT34drfzN3Y+P1KDnlZG4MgJUAuMEJyEMn9wPTqBxTwaapufNA1/cnXo/e1ZKs7SNJ125v46ENYuiRgeeEjO3fGOVvEBegV88/8uUawTIJz1RBsJZNP2JjSJpIAYWSUfqKFAvzEcCkV8RjkDCKaDN5lYEpLMNpSXlRV5DqVYgX/5nfxLid2hn/s0ZFbxV1DXxcffurH+6BVIBaQo1X6nPSAU7C8BDK2lzT3X0HfQEBg0/oZdoWl1qFmKJ9+BByt1a67q+z8t3bWGYf3OefhPhLv21vueefqINkHE0eJ9TjFl3/YX7wQ20M2iHtKoPllWE5IzkxlxUXtxlNPzh17Ab3kgYoS6OdRNQHsvgl2OgRAOB+K6pa2qV9qziqkhgJiL0+Quer8i4jysa9fj68DQ+dutKULYdq3RvuxVmzH8gZJBHs1c0xCsQDo8b4Fl9xHZQb6dbZipnQANnDOK65yxBeNZKY3TIH1Ibsci/kbywv4nt8rE5sIun4t4KGREPrWawvAPn6hrN7HvFfRWnmf/kF4L0AHR6VISdZzB/N/B/HbXJVGuKn7tF50sLy9YMVnT2XjEyMzt2vq12NcbeOTjz3o6KnnBsTOfdJgIOum8lNaBuThadv1Syajsn1/ZEjy4s1s57T+Ia8Z566hwoIqBK8bEHiyvg6XjxcktyKZEATtMfcwE8rL7S5fdCTHBu4buMNGU/6pqWOmlhhH86KNaDfvG1PnmnUWzoXlffnq2NZ/Hg5GhhTvSTWgNQ+qgwBOIdbwZH39NoVoBwwG8wbQmhkptukMrcccRkmRWFkmZTNaNbcBh0vN30KL9xn44T8D+7QgYnws0DfSiSAOcbFEBZGQCGtxiyN5u6tjhz3Qf3aMFs3BH1v8lyhS6WBE5zoDQZgEbx4vM3yepmcUhxdO2U6UdIKfi3ivxRfqhDYL45ZUM8bl9CkdjlFc4TsQP4RCvbXsbKmR7pnZING9k7kc3jNrL+ViQj7RebOiYNvoT5rhXu94nSoIAuFONmenRs8u1lDgihtHJsO03lCwE8Hk5Cmr6Q95eX+0jpL0kySypeiisy1ASNO9f8sbwafLM0+vR78L/RaSSrDJ2CnaXsdx1ezsfW8hOJTxweHHSeNiSDJT7WiV+T6iqH9U8MAstRSHCRmZaeFRnSJAKYR+c1qNCDKV62dlPm4+nlv2Pn4zemXrZ0ZoDl6FsIeIYoLRqfW1Q7ylADuzUc5aBq5WIFBRNLxbkik1Dh2WHLsTVM/IiMv6PfXtNLOc2DOD5Zhn8BchoOfJnL+6/8/CAaMv73EWbhfw8uYeCgiUneLwloftgHp2L7zb6rt+k7EKRsO4gLN9WwWJxKnwnYPJ52jnl7d8YCfleCKt9bOGD4mRf8UaDn4o4JGgmrfsMt5qcnPbmyOPNWc4XTF/YjbWhtciQgHMKtNYyzIBIYdrSlz8zfhaaPldMHf7SHsgdd/Xl05bSKVKLBJUxLkMhyCGOMXA2AEakzVHr1IICFTSfnGKWOWs+nviMPQ07uM=',
          'base64'
        )
      );

      expect(await decryptSymmetricKeyForUser(recipient.privateKey, wrapped, KEM_AD)).toEqual(seq(32, 100));
    });

    it('should refuse to unwrap a key wrapped for another purpose', async () => {
      const user = await generateUserKeyPair();
      const wraps = await encryptSymmetricKeyForUsers(
        await generateSymmetricKey(),
        { user: user.publicKey },
        'lasuite-encryption/kem-device-bootstrap/v1'
      );

      await expect(decryptSymmetricKeyForUser(user.secretKey, wraps['user'], 'lasuite-encryption/kem-document-key/v1')).rejects.toBeInstanceOf(
        VaultError
      );
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
        const encrypted = await encryptContent(content, key, AD);
        expect(await decryptContent(encrypted, key, AD)).toEqual(content);

        const flipped = flipBit(encrypted, seed % (encrypted.length * 8));
        await expect(decryptContent(flipped, key, AD)).rejects.toBeInstanceOf(VaultError);
      }),
      { numRuns: 100 }
    );
  });

  it('decryptContent rejects random bytes with a VaultError', async () => {
    const key = await generateSymmetricKey();

    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 256 }), async (bytes) => {
        await expect(decryptContent(bytes, key, AD)).rejects.toBeInstanceOf(VaultError);
      }),
      { numRuns: 200 }
    );
  });

  it('decryptSymmetricKeyForUser round-trips and rejects any bit flip with a VaultError', async () => {
    const recipient = await generateUserKeyPair();
    const symmetricKey = await generateSymmetricKey();
    const { alice: wrapped } = await encryptSymmetricKeyForUsers(symmetricKey, { alice: recipient.publicKey }, KEM_AD);

    expect(await decryptSymmetricKeyForUser(recipient.secretKey, wrapped, KEM_AD)).toEqual(symmetricKey);

    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 0, max: wrapped.length * 8 - 1 }), async (bit) => {
        await expect(decryptSymmetricKeyForUser(recipient.secretKey, flipBit(wrapped, bit), KEM_AD)).rejects.toBeInstanceOf(VaultError);
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
        await expect(decryptSymmetricKeyForUser(recipient.secretKey, bytes, KEM_AD)).rejects.toBeInstanceOf(VaultError);
      }),
      { numRuns: 200 }
    );
  });
});
