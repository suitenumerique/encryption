import { GetPublicKeysQuerySchema, PublicKeySchema } from '@encryption/src/server/routes/public-keys';

// Importing the route module pulls in src/server/env, which validates the
// process environment at import time and exits when it is missing. These are
// pure schema assertions, so the module is stubbed rather than provisioned.
jest.mock('@encryption/src/server/env', () => ({ env: { OIDC_ISSUER: 'https://issuer.example' } }));

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
    it('should normalize a single occurrence to a one-element array', () => {
      const result = GetPublicKeysQuerySchema.parse({ user_ids: '550e8400-e29b-41d4-a716-446655440000' });

      expect(result.user_ids).toEqual(['550e8400-e29b-41d4-a716-446655440000']);
    });

    it('should keep repeated occurrences in order', () => {
      const valid = { user_ids: ['550e8400-e29b-41d4-a716-446655440000', '660e8400-e29b-41d4-a716-446655440001'] };
      const result = GetPublicKeysQuerySchema.parse(valid);

      expect(result.user_ids).toEqual(['550e8400-e29b-41d4-a716-446655440000', '660e8400-e29b-41d4-a716-446655440001']);
    });

    it('should reject missing user_ids', () => {
      expect(() => GetPublicKeysQuerySchema.parse({})).toThrow();
    });

    it('should reject an empty sub', () => {
      expect(() => GetPublicKeysQuerySchema.parse({ subs: ['kc-sub-1', ''] })).toThrow();
    });

    // Synthetic but well-formed uuids: 100 distinct suffixes over a fixed stem.
    const uuidAt = (i: number) => `550e8400-e29b-41d4-a716-4466554${String(i).padStart(5, '0')}`;

    it('should reject a list longer than 100 ids', () => {
      const tooMany = Array.from({ length: 101 }, (_, i) => uuidAt(i));

      expect(() => GetPublicKeysQuerySchema.parse({ user_ids: tooMany })).toThrow();
    });

    it('should accept a list of exactly 100 ids', () => {
      const exactly = Array.from({ length: 100 }, (_, i) => uuidAt(i));
      const result = GetPublicKeysQuerySchema.parse({ user_ids: exactly });

      expect(result.user_ids).toHaveLength(100);
    });

    it('should reject a non-uuid user id (an OIDC sub does not belong in user_ids)', () => {
      expect(() => GetPublicKeysQuerySchema.parse({ user_ids: 'keycloak-sub-1' })).toThrow();
    });

    it('should accept free-form subs but reject an over-long one', () => {
      expect(GetPublicKeysQuerySchema.parse({ subs: ['kc sub with spaces', 'another#sub'] }).subs).toHaveLength(2);
      expect(() => GetPublicKeysQuerySchema.parse({ subs: 'x'.repeat(201) })).toThrow();
    });

    // A comma is legal in an OIDC sub; the old comma-joined form shattered it
    // into two bogus lookups. Repeated parameters must carry it through intact.
    it('should preserve a comma inside a sub', () => {
      expect(GetPublicKeysQuerySchema.parse({ subs: 'weird,sub' }).subs).toEqual(['weird,sub']);
    });

    it('should reject mixing user_ids and subs (response keying would be ambiguous)', () => {
      expect(() => GetPublicKeysQuerySchema.parse({ user_ids: uuidAt(0), subs: 'kc-sub-1' })).toThrow();
    });
  });
});
