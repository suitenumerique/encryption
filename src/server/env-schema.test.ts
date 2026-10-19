import { readFileSync } from 'node:fs';
import { parseEnv } from 'node:util';
import { describe, expect, it } from 'vitest';

import { exportPublicKeyAsBase64, generateUserKeyPair } from '@encryption/src/crypto';
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

describe('VAULT_DEVICE_INACTIVITY_DAYS', () => {
  const parse = (value: string | undefined) => envSchema.shape.VAULT_DEVICE_INACTIVITY_DAYS.safeParse(value);

  it('defaults to one year, also when set but empty', () => {
    expect(parse(undefined).data).toBe(365);
    expect(parse('').data).toBe(365);
  });

  it('accepts 0 (never de-enroll) and a month or more', () => {
    for (const value of ['0', '30', '180']) {
      expect(parse(value).success, value).toBe(true);
    }
  });

  it('refuses a delay a holiday would exceed', () => {
    for (const value of ['1', '29', '-5', '30.5', 'abc']) {
      expect(parse(value).success, value).toBe(false);
    }
  });
});

describe('OIDC name claims', () => {
  const baseEnv = parseEnv(readFileSync('.env.test', 'utf8'));
  const issuesFor = (overrides: Record<string, string>) =>
    envSchema.safeParse({ ...baseEnv, ...overrides }).error?.issues.map((issue) => issue.path.join('.')) ?? [];

  it('accepts a last name taken from the full name alone', () => {
    expect(issuesFor({ OIDC_CLAIMS_LAST_NAME: '', OIDC_CLAIMS_FULL_NAME: 'name' })).toEqual([]);
  });

  it('refuses a configuration that leaves no way to a last name', () => {
    expect(issuesFor({ OIDC_CLAIMS_LAST_NAME: '', OIDC_CLAIMS_FULL_NAME: '' })).toEqual(['OIDC_CLAIMS_LAST_NAME']);
  });
});

describe('MAINTENANCE_ESCROW_KEYS', () => {
  const parse = (value: string | undefined) => envSchema.shape.MAINTENANCE_ESCROW_KEYS.safeParse(value);

  it('is unset when absent or empty', () => {
    expect(parse(undefined).data).toBeUndefined();
    expect(parse('').data).toBeUndefined();
  });

  it('reads the JSON list, domains lowercased, and refuses at boot a malformed key, domain or document', async () => {
    const key = exportPublicKeyAsBase64((await generateUserKeyPair()).publicKey);

    expect(parse(JSON.stringify([{ domains: ['Agriculture.GOUV.fr', '*'], publicKey: key }])).data).toEqual([
      { domains: ['agriculture.gouv.fr', '*'], publicKey: key },
    ]);

    for (const value of [
      'not json',
      JSON.stringify({ domains: ['*'], publicKey: key }),
      JSON.stringify([{ domains: ['*'], publicKey: 'AAAA' }]),
      JSON.stringify([{ domains: [], publicKey: key }]),
      JSON.stringify([{ domains: ['user@agriculture.gouv.fr'], publicKey: key }]),
      JSON.stringify([{ domains: ['monéquipe.gouv.fr'], publicKey: key }]),
    ]) {
      expect(parse(value).success, value).toBe(false);
    }
  });
});
