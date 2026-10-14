import { describe, expect, it } from 'vitest';

import { envSchema } from '@encryption/src/server/env-schema';

describe('ALLOWED_FRAME_ANCESTORS', () => {
  const parse = (value: string) => envSchema.shape.ALLOWED_FRAME_ANCESTORS.safeParse(value);

  it('accepts a comma-separated list of origins and leftmost wildcards', () => {
    expect(parse('https://docs.example.org, https://*.drive.example.org').success).toBe(true);
  });

  it('refuses a list the CSP would read wider than the vault', () => {
    for (const value of ['*', 'https://docs.example.org,*', 'docs.example.org', '', ' , ']) {
      expect(parse(value).success, value).toBe(false);
    }
  });

  it('names the offending entries', () => {
    const result = parse('https://docs.example.org,*,https://docs.*.example.org');

    expect(result.error?.issues[0].message).toContain('*, https://docs.*.example.org');
  });
});

describe('VAULT_PURGE_AFTER_DAYS', () => {
  const parse = (value: string | undefined) => envSchema.shape.VAULT_PURGE_AFTER_DAYS.safeParse(value);

  it('defaults to two years, also when set but empty', () => {
    expect(parse(undefined).data).toBe(730);
    expect(parse('').data).toBe(730);
  });

  it('accepts 0 (never purge) and six months or more', () => {
    for (const value of ['0', '180', '3650']) {
      expect(parse(value).success, value).toBe(true);
    }
  });

  it('refuses a retention shorter than six months', () => {
    for (const value of ['1', '90', '179', '-1', '200.5']) {
      expect(parse(value).success, value).toBe(false);
    }
  });
});
