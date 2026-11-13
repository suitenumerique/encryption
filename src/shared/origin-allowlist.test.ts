import { describe, expect, it } from 'vitest';

import { isOriginInAllowlist, isValidOriginEntry, parseOriginAllowlist } from '@encryption/src/shared/origin-allowlist';

describe('parseOriginAllowlist', () => {
  it('splits, trims and drops empty entries', () => {
    expect(parseOriginAllowlist(' https://a.example , https://*.b.example,, ')).toEqual(['https://a.example', 'https://*.b.example']);
  });
});

describe('isOriginInAllowlist', () => {
  const allowlist = ['https://docs.example.org', 'https://*.drive.example.org'];

  it('matches an exact origin, and a wildcard at any depth', () => {
    expect(isOriginInAllowlist('https://docs.example.org', allowlist)).toBe(true);
    expect(isOriginInAllowlist('https://team.drive.example.org', allowlist)).toBe(true);
    expect(isOriginInAllowlist('https://a.team.drive.example.org', allowlist)).toBe(true);
  });

  it('rejects the wildcard base itself, look-alikes and another scheme', () => {
    expect(isOriginInAllowlist('https://drive.example.org', allowlist)).toBe(false);
    expect(isOriginInAllowlist('https://evildrive.example.org', allowlist)).toBe(false);
    expect(isOriginInAllowlist('https://team.drive.example.org.evil.example', allowlist)).toBe(false);
    expect(isOriginInAllowlist('http://team.drive.example.org', allowlist)).toBe(false);
    expect(isOriginInAllowlist('null', allowlist)).toBe(false);
  });
});

describe('isValidOriginEntry', () => {
  it('accepts origins and leftmost wildcards as the browser writes them', () => {
    for (const entry of ['https://docs.example.org', 'http://localhost:7201', 'https://*.example.org', 'http://*.product.localhost:7201']) {
      expect(isValidOriginEntry(entry), entry).toBe(true);
    }
  });

  it('refuses what the CSP and the vault would read differently', () => {
    for (const entry of [
      '*',
      'https://*',
      'https://*.',
      'docs.example.org',
      '*.example.org',
      'https://docs.*.example.org',
      'https://*.*.example.org',
      'https://docs.example.org/',
      'https://docs.example.org/path',
      'https://Docs.example.org',
      'ftp://docs.example.org',
      "'self'",
    ]) {
      expect(isValidOriginEntry(entry), entry).toBe(false);
    }
  });
});
