import sodium from 'libsodium-wrappers-sumo';

import { ensureSodium, generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { base64ToUint8, exportPublicKeyAsBase64, importPublicKeyFromBase64 } from '@encryption/src/crypto/encryption-backup';
import { CRYPTO_VERSION } from '@encryption/src/shared/constants';

describe('encryption-backup', () => {
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
