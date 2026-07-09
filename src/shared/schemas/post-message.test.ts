import {
  PRIVILEGED_OPERATIONS,
  VaultPrivilegedRequestSchema,
  VaultProductRequestSchema,
  VaultRequestSchema,
} from '@encryption/src/shared/schemas/post-message';

describe('post-message schemas', () => {
  describe('VaultProductRequestSchema', () => {
    it('should accept valid product operations', () => {
      const valid = { type: 'vault:has-keys', requestId: '123' };
      expect(() => VaultProductRequestSchema.parse(valid)).not.toThrow();
    });

    it('should accept encrypt-without-key request with payload', () => {
      const valid = {
        type: 'vault:encrypt-without-key',
        requestId: '123',
        payload: { data: 'base64data', userPublicKeys: { user1: 'key1' } },
      };
      expect(() => VaultProductRequestSchema.parse(valid)).not.toThrow();
    });

    it('should accept share-keys request with payload', () => {
      const valid = {
        type: 'vault:share-keys',
        requestId: '123',
        payload: { encryptedSymmetricKey: 'key', userPublicKeys: { user1: 'key1' } },
      };
      expect(() => VaultProductRequestSchema.parse(valid)).not.toThrow();
    });

    it('should reject privileged operations', () => {
      const invalid = { type: 'vault:generate-keys', requestId: '123' };
      expect(() => VaultProductRequestSchema.parse(invalid)).toThrow();
    });

    it('should reject unknown operations', () => {
      const invalid = { type: 'vault:unknown', requestId: '123' };
      expect(() => VaultProductRequestSchema.parse(invalid)).toThrow();
    });
  });

  describe('VaultPrivilegedRequestSchema', () => {
    it('should accept generate-keys', () => {
      const valid = { type: 'vault:generate-keys', requestId: '123' };
      expect(() => VaultPrivilegedRequestSchema.parse(valid)).not.toThrow();
    });

    it('should accept destroy-keys', () => {
      const valid = { type: 'vault:destroy-keys', requestId: '123' };
      expect(() => VaultPrivilegedRequestSchema.parse(valid)).not.toThrow();
    });

    it('should reject product operations', () => {
      const invalid = { type: 'vault:encrypt-without-key', requestId: '123', payload: { data: 'test', userPublicKeys: {} } };
      expect(() => VaultPrivilegedRequestSchema.parse(invalid)).toThrow();
    });
  });

  describe('PRIVILEGED_OPERATIONS set', () => {
    it('should contain all sensitive operations', () => {
      expect(PRIVILEGED_OPERATIONS.has('vault:generate-keys')).toBe(true);
      expect(PRIVILEGED_OPERATIONS.has('vault:destroy-keys')).toBe(true);
      expect(PRIVILEGED_OPERATIONS.has('vault:accept-fingerprint')).toBe(true);
      expect(PRIVILEGED_OPERATIONS.has('vault:refuse-fingerprint')).toBe(true);
    });

    it('should NOT contain product operations', () => {
      expect(PRIVILEGED_OPERATIONS.has('vault:has-keys')).toBe(false);
      expect(PRIVILEGED_OPERATIONS.has('vault:encrypt-without-key')).toBe(false);
      expect(PRIVILEGED_OPERATIONS.has('vault:decrypt-with-key')).toBe(false);
      expect(PRIVILEGED_OPERATIONS.has('vault:get-public-key')).toBe(false);
      expect(PRIVILEGED_OPERATIONS.has('vault:check-fingerprints')).toBe(false);
      expect(PRIVILEGED_OPERATIONS.has('vault:get-known-fingerprints')).toBe(false);
    });
  });

  describe('VaultRequestSchema (combined)', () => {
    it('should accept both product and privileged operations', () => {
      expect(() => VaultRequestSchema.parse({ type: 'vault:has-keys', requestId: '1' })).not.toThrow();
      expect(() => VaultRequestSchema.parse({ type: 'vault:generate-keys', requestId: '2' })).not.toThrow();
    });
  });
});
