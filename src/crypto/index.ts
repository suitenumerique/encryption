export {
  ensureSodium,
  generateUserKeyPair,
  generateSymmetricKey,
  encryptContent,
  decryptContent,
  hybridEncapsulate,
  hybridDecapsulate,
  encryptSymmetricKeyForUsers,
  decryptSymmetricKeyForUser,
  writeUint16LE,
  readUint16LE,
  writeUint32LE,
  readUint32LE,
  type HybridKeyPair,
  type HybridPublicKey,
  type HybridSecretKey,
} from '@encryption/src/crypto/encryption';

export {
  keyPairToPassphrase,
  passphraseToKeyPair,
  exportPublicKeyAsBase64,
  importPublicKeyFromBase64,
  uint8ToBase64,
  base64ToUint8,
} from '@encryption/src/crypto/encryption-backup';

export { getEncryptionDB } from '@encryption/src/crypto/encryption-db';

export { computeKeyFingerprint, formatFingerprint } from '@encryption/src/crypto/fingerprint';
