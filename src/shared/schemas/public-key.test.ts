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
    it('should accept comma-separated user_ids', () => {
      const valid = { user_ids: '550e8400-e29b-41d4-a716-446655440000,660e8400-e29b-41d4-a716-446655440001' };
      const result = GetPublicKeysQuerySchema.parse(valid);

      expect(result.user_ids).toContain(',');
    });

    it('should reject missing user_ids', () => {
      expect(() => GetPublicKeysQuerySchema.parse({})).toThrow();
    });
  });
});
