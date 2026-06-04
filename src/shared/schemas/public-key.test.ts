import { GetPublicKeysQuerySchema, PublicKeySchema } from '@encryption/src/shared/schemas/public-key';

describe('public-key schemas', () => {
  describe('PublicKeySchema', () => {
    it('should accept valid public key data', () => {
      const valid = { user_id: '550e8400-e29b-41d4-a716-446655440000', public_key: 'base64data' };
      const result = PublicKeySchema.parse(valid);

      expect(result.user_id).toBe('550e8400-e29b-41d4-a716-446655440000');
      expect(result.public_key).toBe('base64data');
    });

    it('should reject empty user_id', () => {
      const invalid = { user_id: '', public_key: 'base64data' };

      expect(() => PublicKeySchema.parse(invalid)).toThrow();
    });

    it('should reject missing public_key', () => {
      const invalid = { user_id: '550e8400-e29b-41d4-a716-446655440000' };

      expect(() => PublicKeySchema.parse(invalid)).toThrow();
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
