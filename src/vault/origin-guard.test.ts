import { initOriginGuard, isInterfaceOrigin, isOriginAllowed } from '@encryption/src/vault/origin-guard';

describe('origin-guard', () => {
  beforeEach(() => {
    initOriginGuard(
      ['https://docs.numerique.gouv.fr', 'https://drive.numerique.gouv.fr', 'https://*.numerique.gouv.fr', 'http://localhost:7200'],
      'https://encryption.numerique.gouv.fr'
    );
  });

  describe('isOriginAllowed', () => {
    it('should allow exact match origins', () => {
      expect(isOriginAllowed('https://docs.numerique.gouv.fr')).toBe(true);
      expect(isOriginAllowed('https://drive.numerique.gouv.fr')).toBe(true);
      expect(isOriginAllowed('http://localhost:7200')).toBe(true);
    });

    it('should allow wildcard subdomain matches', () => {
      expect(isOriginAllowed('https://fichier.numerique.gouv.fr')).toBe(true);
      expect(isOriginAllowed('https://visio.numerique.gouv.fr')).toBe(true);
    });

    it('should reject origins not in the allowed list', () => {
      expect(isOriginAllowed('https://evil.com')).toBe(false);
      expect(isOriginAllowed('https://numerique.gouv.fr.evil.com')).toBe(false);
      expect(isOriginAllowed('http://localhost:9999')).toBe(false);
    });

    it('should reject deep subdomains with single wildcard', () => {
      expect(isOriginAllowed('https://a.b.numerique.gouv.fr')).toBe(false);
    });

    it('should reject empty origin', () => {
      expect(isOriginAllowed('')).toBe(false);
    });
  });

  describe('isInterfaceOrigin', () => {
    it('should return true for the encryption origin', () => {
      expect(isInterfaceOrigin('https://encryption.numerique.gouv.fr')).toBe(true);
    });

    it('should return false for any other origin', () => {
      expect(isInterfaceOrigin('https://docs.numerique.gouv.fr')).toBe(false);
      expect(isInterfaceOrigin('https://evil.com')).toBe(false);
      expect(isInterfaceOrigin('http://localhost:7200')).toBe(false);
    });

    it('should return false when no interface origin is configured', () => {
      initOriginGuard(['http://localhost:7200'], null);

      expect(isInterfaceOrigin('http://localhost:7200')).toBe(false);
    });
  });
});
