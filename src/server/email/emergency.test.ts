import { describe, expect, it, vi } from 'vitest';

import { senderFor } from '@encryption/src/server/email/emergency';

// The module reads the server env at import time
vi.mock('@encryption/src/server/env', () => ({ env: { MAILER_SENDER_ADDRESS: 'chiffrement@example.org' } }));

describe('senderFor', () => {
  it("names the sender in the recipient's language, from the operator's address", () => {
    expect(senderFor('fr')).toEqual({ name: 'LaSuite Chiffrement', address: 'chiffrement@example.org' });
    expect(senderFor('en')).toEqual({ name: 'LaSuite Encryption', address: 'chiffrement@example.org' });
  });

  it('falls back to English for a language the service is not translated in', () => {
    expect(senderFor('de').name).toBe('LaSuite Encryption');
  });
});
