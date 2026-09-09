import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { base64ToUint8, exportPublicKeyAsBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import {
  type SerializedKeyRegistration,
  encodeIdentityContinuityPayload,
  encodeKeyRegistrationPayload,
  encodePopChallengeMessage,
  verifyIdentityContinuity,
  verifyKeyRegistration,
} from '@encryption/src/crypto/key-registration';
import { generateSignatureKeyPair, signDetached } from '@encryption/src/crypto/signature';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

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

  describe('verifyIdentityContinuity', () => {
    // Endorse a fresh identity with a previous identity key, then return the
    // wire views the verifier consumes.
    async function buildContinuity(overrides: Partial<{ userId: string; generation: number; algo: string }> = {}) {
      const previous = await generateSignatureKeyPair();
      const next = await generateSignatureKeyPair();

      const userId = overrides.userId ?? 'user-123';
      const generation = overrides.generation ?? 2;
      const algo = overrides.algo ?? 'ed25519';

      const nextSignaturePublicKeyB64 = exportPublicKeyAsBase64(next.publicKey);
      const record = {
        userId,
        generation,
        algo,
        signaturePublicKeyWire: base64ToUint8(nextSignaturePublicKeyB64),
      };

      const continuitySignatureB64 = uint8ToBase64(await signDetached(encodeIdentityContinuityPayload(record), previous.secretKey));
      const previousSignaturePublicKeyB64 = exportPublicKeyAsBase64(previous.publicKey);

      return { record, continuitySignatureB64, previousSignaturePublicKeyB64, previous, next };
    }

    it('verifies an identity endorsed by the previous identity key', async () => {
      const { record, previousSignaturePublicKeyB64, continuitySignatureB64 } = await buildContinuity();

      expect(await verifyIdentityContinuity(record, previousSignaturePublicKeyB64, continuitySignatureB64)).toBe(true);
    });

    it('rejects an endorsement verified against the wrong previous key', async () => {
      const { record, continuitySignatureB64 } = await buildContinuity();
      const impostor = await generateSignatureKeyPair();

      expect(await verifyIdentityContinuity(record, exportPublicKeyAsBase64(impostor.publicKey), continuitySignatureB64)).toBe(false);
    });

    it('rejects when the endorsed generation is tampered', async () => {
      const { record, previousSignaturePublicKeyB64, continuitySignatureB64 } = await buildContinuity({ generation: 2 });

      expect(await verifyIdentityContinuity({ ...record, generation: 3 }, previousSignaturePublicKeyB64, continuitySignatureB64)).toBe(false);
    });

    it('rejects a malformed continuity signature without throwing', async () => {
      const { record, previousSignaturePublicKeyB64 } = await buildContinuity();

      expect(await verifyIdentityContinuity(record, previousSignaturePublicKeyB64, 'not-base64-???')).toBe(false);
    });
  });
});

describe('canonical payload encoding (property)', () => {
  const text = fc.string({ unit: 'grapheme', maxLength: 24 });
  const bytes = fc.uint8Array({ maxLength: 48 });

  const registration = fc.record({
    userId: text,
    version: fc.nat(),
    createdAtMillis: fc.maxSafeNat(),
    encryptionPublicKeyWire: bytes,
    signaturePublicKeyWire: bytes,
  });

  const continuity = fc.record({ userId: text, generation: fc.nat(), algo: text, signaturePublicKeyWire: bytes });

  const canonical = (record: object): string => JSON.stringify(record, (_, v) => (v instanceof Uint8Array ? Array.from(v) : v));
  const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

  it('encodeKeyRegistrationPayload is injective', () => {
    fc.assert(
      fc.property(registration, registration, (a, b) => {
        expect(sameBytes(encodeKeyRegistrationPayload(a), encodeKeyRegistrationPayload(b))).toBe(canonical(a) === canonical(b));
      })
    );
  });

  it('encodeIdentityContinuityPayload is injective', () => {
    fc.assert(
      fc.property(continuity, continuity, (a, b) => {
        expect(sameBytes(encodeIdentityContinuityPayload(a), encodeIdentityContinuityPayload(b))).toBe(canonical(a) === canonical(b));
      })
    );
  });

  it('refuses a field the 16-bit length prefix cannot represent instead of wrapping it', () => {
    const oversized = new Uint8Array(0x10000);

    expect(() =>
      encodeKeyRegistrationPayload({
        userId: 'u',
        version: 1,
        createdAtMillis: 0,
        encryptionPublicKeyWire: oversized,
        signaturePublicKeyWire: oversized,
      })
    ).toThrow(expect.objectContaining({ code: VaultErrorCode.INVALID_CANONICAL_PAYLOAD }));
  });

  it('refuses a timestamp that is not an unsigned safe integer', () => {
    for (const createdAtMillis of [-1, 1.5, Number.MAX_SAFE_INTEGER + 2, NaN]) {
      expect(() =>
        encodeKeyRegistrationPayload({
          userId: 'u',
          version: 1,
          createdAtMillis,
          encryptionPublicKeyWire: new Uint8Array(1),
          signaturePublicKeyWire: new Uint8Array(1),
        })
      ).toThrow(VaultError);
    }
  });

  it('verifyKeyRegistration returns false, never throws, on arbitrary wire records', async () => {
    const wire = fc.record({
      userId: text,
      version: fc.nat(),
      createdAtMillis: fc.maxSafeNat(),
      encryptionPublicKeyB64: fc.oneof(text, bytes.map(uint8ToBase64)),
      signaturePublicKeyB64: fc.oneof(text, bytes.map(uint8ToBase64)),
      keyBindingSignatureB64: fc.oneof(text, bytes.map(uint8ToBase64)),
    });

    await fc.assert(
      fc.asyncProperty(wire, async (record) => {
        expect(await verifyKeyRegistration(record)).toBe(false);
      })
    );
  });
});
