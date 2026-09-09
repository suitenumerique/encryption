import fc from 'fast-check';
import { beforeEach, describe, expect, it } from 'vitest';

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

describe('isOriginAllowed wildcard matching (property)', () => {
  const label = fc.stringMatching(/^[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?$/);
  // A numeric last label would parse as an IPv4 address, not a domain.
  const tld = fc.stringMatching(/^[a-z]{2,6}$/);
  const base = fc.tuple(fc.array(label, { minLength: 1, maxLength: 2 }), tld).map(([parts, t]) => [...parts, t].join('.'));
  // Hand-built rather than fc.webUrl(): that generator costs ~200ms to construct.
  const origin = fc
    .tuple(
      fc.constantFrom('http', 'https'),
      fc.array(label, { minLength: 1, maxLength: 4 }),
      tld,
      fc.option(fc.integer({ min: 1, max: 65535 }), { nil: undefined })
    )
    .map(([scheme, labels, t, port]) => `${scheme}://${[...labels, t].join('.')}${port === undefined ? '' : `:${port}`}`);

  it('accepts exactly the hosts one label below the wildcard base', () => {
    fc.assert(
      fc.property(base, label, fc.constantFrom('one-level', 'deep', 'base-itself', 'dot-replaced', 'suffixed', 'other-port'), (b, l, shape) => {
        initOriginGuard([`https://*.${b}`], null);

        const host =
          shape === 'one-level'
            ? `${l}.${b}`
            : shape === 'deep'
              ? `${l}.${l}.${b}`
              : shape === 'base-itself'
                ? b
                : shape === 'dot-replaced'
                  ? `${l}.${b.replace('.', l.charAt(0))}`
                  : shape === 'suffixed'
                    ? `${l}.${b}.${l}`
                    : `${l}.${b}:8443`;

        expect(isOriginAllowed(`https://${host}`)).toBe(shape === 'one-level');
      })
    );
  });

  it('never accepts a random origin whose host is not one label below the base', () => {
    fc.assert(
      fc.property(base, origin, (b, o) => {
        initOriginGuard([`https://*.${b}`], null);

        const { host } = new URL(o);
        const oneLabelBelow = o.startsWith('https://') && host.endsWith(`.${b}`) && !host.slice(0, -(b.length + 1)).includes('.');

        expect(isOriginAllowed(o)).toBe(oneLabelBelow);
      })
    );
  });

  it('treats every non-wildcard entry as a byte-for-byte match', () => {
    fc.assert(
      fc.property(origin, origin, (a, b) => {
        initOriginGuard([a], null);

        expect(isOriginAllowed(b)).toBe(a === b);
      })
    );
  });
});
