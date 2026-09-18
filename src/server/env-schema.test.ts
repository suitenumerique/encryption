import { describe, expect, it } from 'vitest';

import { exportPublicKeyAsBase64, generateUserKeyPair } from '@encryption/src/crypto';
import { envSchema } from '@encryption/src/server/env-schema';

const REQUIRED = {
  DATABASE_URL: 'postgresql://x',
  VAULT_URL: 'https://data.encryption.example.org',
  UI_URL: 'https://encryption.example.org',
  ALLOWED_FRAME_ANCESTORS: 'https://docs.example.org',
  OIDC_JWKS_URL: 'https://auth.example.org/jwks',
  OIDC_SERVER_CLIENT_ID: 'encryption',
  OIDC_ISSUER: 'https://auth.example.org',
  OIDC_CLIENT_ID: 'encryption',
  OIDC_REDIRECT_URI: 'https://encryption.example.org/auth/callback',
  MAILER_SMTP_HOST: 'smtp.example.org',
  MAILER_DEFAULT_DOMAIN: 'example.org',
  EMAIL_PRODUCT_URL: 'https://docs.example.org',
};

describe('envSchema', () => {
  it('treats an empty MAINTENANCE_ESCROW_PUBLIC_KEY as unset', () => {
    expect(envSchema.parse({ ...REQUIRED, MAINTENANCE_ESCROW_PUBLIC_KEY: '' }).MAINTENANCE_ESCROW_PUBLIC_KEY).toBeUndefined();
    expect(envSchema.parse(REQUIRED).MAINTENANCE_ESCROW_PUBLIC_KEY).toBeUndefined();
  });

  it('accepts a registry-format X-Wing public key and refuses anything else at boot', async () => {
    const pair = await generateUserKeyPair();
    const key = exportPublicKeyAsBase64(pair.publicKey);

    expect(envSchema.parse({ ...REQUIRED, MAINTENANCE_ESCROW_PUBLIC_KEY: key }).MAINTENANCE_ESCROW_PUBLIC_KEY).toBe(key);

    for (const bad of ['AAAA', key.slice(0, -12), 'not base64']) {
      const result = envSchema.safeParse({ ...REQUIRED, MAINTENANCE_ESCROW_PUBLIC_KEY: bad });

      expect(result.success).toBe(false);
      expect(JSON.stringify(result.error?.issues)).toContain('MAINTENANCE_ESCROW_PUBLIC_KEY');
    }
  });
});
