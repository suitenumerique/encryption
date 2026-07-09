import { GetPublicKeysQuerySchema, PublicKeySchema } from '@encryption/src/shared/schemas/public-key';

describe('public-key schemas', () => {
  const validEntry = {
    user_id: '550e8400-e29b-41d4-a716-446655440000',
    encryption_public_key: 'encBase64',
    signature_public_key: 'sigBase64',
    key_binding_signature: 'sigOverPayload',
    version: 1,
    created_at_millis: 1_700_000_000_000,
  };

  describe('PublicKeySchema', () => {
    it('should accept a full registry entry', () => {
      const result = PublicKeySchema.parse(validEntry);

      expect(result.user_id).toBe(validEntry.user_id);
      expect(result.encryption_public_key).toBe('encBase64');
      expect(result.signature_public_key).toBe('sigBase64');
      expect(result.key_binding_signature).toBe('sigOverPayload');
      expect(result.version).toBe(1);
      expect(result.created_at_millis).toBe(1_700_000_000_000);
    });

    it('should reject empty user_id', () => {
      expect(() => PublicKeySchema.parse({ ...validEntry, user_id: '' })).toThrow();
    });

    it('should reject a missing signature_public_key', () => {
      const { signature_public_key: _omit, ...invalid } = validEntry;

      expect(() => PublicKeySchema.parse(invalid)).toThrow();
    });

    it('should reject a non-positive version', () => {
      expect(() => PublicKeySchema.parse({ ...validEntry, version: 0 })).toThrow();
    });
  });

  describe('GetPublicKeysQuerySchema', () => {
    it('should split and trim comma-separated user_ids into an array', () => {
      const valid = { user_ids: '550e8400-e29b-41d4-a716-446655440000, 660e8400-e29b-41d4-a716-446655440001' };
      const result = GetPublicKeysQuerySchema.parse(valid);

      expect(result.user_ids).toEqual(['550e8400-e29b-41d4-a716-446655440000', '660e8400-e29b-41d4-a716-446655440001']);
    });

    it('should reject missing user_ids', () => {
      expect(() => GetPublicKeysQuerySchema.parse({})).toThrow();
    });

    it('should reject an empty user id (e.g. a trailing comma)', () => {
      expect(() => GetPublicKeysQuerySchema.parse({ user_ids: 'a,' })).toThrow();
    });

    it('should reject a list longer than 100 ids', () => {
      const tooMany = Array.from({ length: 101 }, (_, i) => `u${i}`).join(',');

      expect(() => GetPublicKeysQuerySchema.parse({ user_ids: tooMany })).toThrow();
    });

    it('should accept a list of exactly 100 ids', () => {
      const exactly = Array.from({ length: 100 }, (_, i) => `u${i}`).join(',');
      const result = GetPublicKeysQuerySchema.parse({ user_ids: exactly });

      expect(result.user_ids).toHaveLength(100);
    });

    it('should reject an over-long single user id', () => {
      expect(() => GetPublicKeysQuerySchema.parse({ user_ids: 'x'.repeat(201) })).toThrow();
    });
  });
});
