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
  type UserKeyBundle,
  keyPairToPassphrase,
  passphraseToKeyPair,
  exportPublicKeyAsBase64,
  importPublicKeyFromBase64,
  uint8ToBase64,
  base64ToUint8,
} from '@encryption/src/crypto/encryption-backup';

export { getEncryptionDB } from '@encryption/src/crypto/encryption-db';

export { computeKeyFingerprint, formatFingerprint } from '@encryption/src/crypto/fingerprint';

export {
  type SignaturePublicKey,
  type SignatureSecretKey,
  type SignatureKeyPair,
  generateSignatureKeyPair,
  signDetached,
  verifyDetached,
  assertValidSignaturePublicKey,
} from '@encryption/src/crypto/signature';

export {
  type KeyRegistrationRecord,
  type SerializedKeyRegistration,
  type IdentityContinuityRecord,
  encodeKeyRegistrationPayload,
  encodePopChallengeMessage,
  encodeIdentityContinuityPayload,
  verifyKeyRegistration,
  verifyIdentityContinuity,
} from '@encryption/src/crypto/key-registration';
