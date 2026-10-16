import Fastify from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { env } from '@encryption/src/server/env';
import { SECURITY_TXT_PATH, buildSecurityTxt, securityTxtRoute } from '@encryption/src/server/routes/security-txt';

vi.mock('@encryption/src/server/env', () => ({
  env: {
    UI_URL: 'https://encryption.example',
    VAULT_URL: 'https://data.encryption.example',
    SECURITY_CONTACT_URL: undefined as string | undefined,
  },
}));

describe('security.txt', () => {
  beforeEach(() => {
    env.SECURITY_CONTACT_URL = 'mailto:security@operator.example';
  });

  it('carries the fields RFC 9116 requires, with an expiry computed from now', () => {
    const text = buildSecurityTxt('mailto:security@operator.example', new Date('2026-01-01T00:00:00.000Z'));

    expect(text).toContain('Contact: mailto:security@operator.example');
    expect(text).toContain('Expires: 2026-01-31T00:00:00.000Z');
    expect(text).toContain('Canonical: https://encryption.example/.well-known/security.txt');
    expect(text).toContain('Canonical: https://data.encryption.example/.well-known/security.txt');
    expect(text).toContain('Policy: https://github.com/suitenumerique/encryption/blob/main/SECURITY.md');
    expect(text.endsWith('\n')).toBe(true);
  });

  it('is served as plain text on any host', async () => {
    const app = Fastify();
    await app.register(securityTxtRoute);

    for (const host of ['encryption.example', 'data.encryption.example']) {
      const response = await app.inject({ method: 'GET', url: SECURITY_TXT_PATH, headers: { host } });

      expect(response.statusCode).toBe(200);
      expect(response.headers['content-type']).toContain('text/plain');
      expect(response.body).toContain('Contact: mailto:security@operator.example');
    }
  });

  it('does not exist when the operator set no contact', async () => {
    env.SECURITY_CONTACT_URL = undefined;
    const app = Fastify();
    await app.register(securityTxtRoute);

    const response = await app.inject({ method: 'GET', url: SECURITY_TXT_PATH });

    expect(response.statusCode).toBe(404);
  });
});
