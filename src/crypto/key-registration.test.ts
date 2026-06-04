import { generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { base64ToUint8, exportPublicKeyAsBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import {
  type SerializedKeyRegistration,
  encodeKeyRegistrationPayload,
  encodePopChallengeMessage,
  verifyKeyRegistration,
} from '@encryption/src/crypto/key-registration';
import { generateSignatureKeyPair, signDetached } from '@encryption/src/crypto/signature';

// Build a fully-signed registration record the way the vault would, then return
// the on-the-wire (base64) view that verifyKeyRegistration consumes.
async function buildSignedRecord(overrides: Partial<{ userId: string; version: number; createdAtMillis: number }> = {}) {
  const encryption = await generateUserKeyPair();
  const signature = await generateSignatureKeyPair();

  const userId = overrides.userId ?? 'user-123';
  const version = overrides.version ?? 1;
  const createdAtMillis = overrides.createdAtMillis ?? 1_700_000_000_000;

  const encryptionPublicKeyB64 = exportPublicKeyAsBase64(encryption.publicKey);
  const signaturePublicKeyB64 = exportPublicKeyAsBase64(signature.publicKey);

  const message = encodeKeyRegistrationPayload({
    userId,
    version,
    createdAtMillis,
    encryptionPublicKeyWire: base64ToUint8(encryptionPublicKeyB64),
    signaturePublicKeyWire: base64ToUint8(signaturePublicKeyB64),
  });

  const keyBindingSignatureB64 = uint8ToBase64(await signDetached(message, signature.secretKey));

  const record: SerializedKeyRegistration = {
    userId,
    version,
    createdAtMillis,
    encryptionPublicKeyB64,
    signaturePublicKeyB64,
    keyBindingSignatureB64,
  };

  return { record, encryption, signature };
}

describe('key-registration', () => {
  describe('encodeKeyRegistrationPayload', () => {
    it('is deterministic for the same record', async () => {
      const { record } = await buildSignedRecord();
      const args = {
        userId: record.userId,
        version: record.version,
        createdAtMillis: record.createdAtMillis,
        encryptionPublicKeyWire: base64ToUint8(record.encryptionPublicKeyB64),
        signaturePublicKeyWire: base64ToUint8(record.signaturePublicKeyB64),
      };

      expect(encodeKeyRegistrationPayload(args)).toEqual(encodeKeyRegistrationPayload(args));
    });

    it('changes when the version changes', async () => {
      const { record } = await buildSignedRecord();
      const base = {
        userId: record.userId,
        createdAtMillis: record.createdAtMillis,
        encryptionPublicKeyWire: base64ToUint8(record.encryptionPublicKeyB64),
        signaturePublicKeyWire: base64ToUint8(record.signaturePublicKeyB64),
      };

      expect(encodeKeyRegistrationPayload({ ...base, version: 1 })).not.toEqual(encodeKeyRegistrationPayload({ ...base, version: 2 }));
    });
  });

  describe('verifyKeyRegistration', () => {
    it('verifies a well-formed signed record', async () => {
      const { record } = await buildSignedRecord();

      expect(await verifyKeyRegistration(record)).toBe(true);
    });

    it('rejects a record with a tampered version', async () => {
      const { record } = await buildSignedRecord();

      expect(await verifyKeyRegistration({ ...record, version: record.version + 1 })).toBe(false);
    });

    it('rejects a record with a tampered creation timestamp', async () => {
      const { record } = await buildSignedRecord();

      expect(await verifyKeyRegistration({ ...record, createdAtMillis: record.createdAtMillis + 1 })).toBe(false);
    });

    it('rejects a record with a tampered userId', async () => {
      const { record } = await buildSignedRecord();

      expect(await verifyKeyRegistration({ ...record, userId: 'someone-else' })).toBe(false);
    });

    it('rejects a record whose encryption key was swapped (identity binding broken)', async () => {
      const { record } = await buildSignedRecord();
      const other = await generateUserKeyPair();

      expect(await verifyKeyRegistration({ ...record, encryptionPublicKeyB64: exportPublicKeyAsBase64(other.publicKey) })).toBe(false);
    });

    it('rejects a record whose identity key was swapped', async () => {
      const { record } = await buildSignedRecord();
      const otherIdentity = await generateSignatureKeyPair();

      expect(await verifyKeyRegistration({ ...record, signaturePublicKeyB64: exportPublicKeyAsBase64(otherIdentity.publicKey) })).toBe(false);
    });

    it('returns false (not throw) for a malformed signature blob', async () => {
      const { record } = await buildSignedRecord();

      expect(await verifyKeyRegistration({ ...record, keyBindingSignatureB64: 'not-base64-???' })).toBe(false);
    });
  });

  describe('encodePopChallengeMessage', () => {
    it('binds distinct challenge ids to distinct messages', () => {
      expect(encodePopChallengeMessage('a')).not.toEqual(encodePopChallengeMessage('b'));
    });
  });
});
