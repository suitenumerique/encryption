import sodium from 'libsodium-wrappers-sumo';

import { ensureSodium, generateUserKeyPair } from '@encryption/src/crypto/encryption';
import {
  base64ToUint8,
  exportPublicKeyAsBase64,
  importPublicKeyFromBase64,
  keyPairToPassphrase,
  passphraseToKeyPair,
} from '@encryption/src/crypto/encryption-backup';
import { CRYPTO_VERSION } from '@encryption/src/shared/constants';

describe('encryption-backup', () => {
  describe('keyPairToPassphrase / passphraseToKeyPair', () => {
    it('should roundtrip an X-Wing key pair through passphrase encoding', async () => {
      const keyPair = await generateUserKeyPair();

      const passphrase = keyPairToPassphrase(keyPair);
      expect(typeof passphrase).toBe('string');
      expect(passphrase.length).toBeGreaterThan(0);

      const restored = passphraseToKeyPair(passphrase);
      expect(restored.publicKey).toEqual(keyPair.publicKey);
      expect(restored.secretKey).toEqual(keyPair.secretKey);
    });

    it('should reject a passphrase with an unsupported version', async () => {
      const keyPair = await generateUserKeyPair();
      const passphrase = keyPairToPassphrase(keyPair);

      // Decode → tamper version → re-encode
      const json = new TextDecoder().decode(base64ToUint8(passphrase.replace(/-/g, '+').replace(/_/g, '/')));
      const tampered = json.replace(`"version":${CRYPTO_VERSION}`, '"version":999');
      const reencoded = btoa(tampered).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

      expect(() => passphraseToKeyPair(reencoded)).toThrow(/unsupported crypto version/i);
    });
  });

  describe('exportPublicKeyAsBase64 / importPublicKeyFromBase64', () => {
    it('should roundtrip an X-Wing public key through the wire format', async () => {
      await ensureSodium();
      const keyPair = await generateUserKeyPair();

      const base64 = exportPublicKeyAsBase64(keyPair.publicKey);
      expect(typeof base64).toBe('string');

      const decoded = base64ToUint8(base64);
      // [version:1][xwingPublicKey:1216]
      expect(decoded[0]).toBe(CRYPTO_VERSION);
      expect(decoded.length).toBe(1 + sodium.crypto_kem_xwing_PUBLICKEYBYTES);

      const imported = importPublicKeyFromBase64(base64);
      expect(imported).toEqual(keyPair.publicKey);
    });

    it('should reject a public key blob with an unknown version byte', async () => {
      const keyPair = await generateUserKeyPair();
      const base64 = exportPublicKeyAsBase64(keyPair.publicKey);
      const blob = base64ToUint8(base64);
      blob[0] = 0xff;
      const tampered = btoa(String.fromCharCode(...blob));

      expect(() => importPublicKeyFromBase64(tampered)).toThrow(/unsupported crypto version/i);
    });
  });
});
