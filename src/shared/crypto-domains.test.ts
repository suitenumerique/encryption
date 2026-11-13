import { describe, expect, it } from 'vitest';

import * as domains from '@encryption/src/shared/crypto-domains';

describe('crypto domain labels', () => {
  const labels = Object.entries(domains).filter(([name]) => name.startsWith('DOMAIN_'));

  it('all follow lasuite-encryption/<purpose>/v<n>', () => {
    for (const [name, label] of labels) {
      expect(label, name).toMatch(/^lasuite-encryption\/[a-z0-9-]+\/v\d+$/);
    }
  });

  it('are all distinct', () => {
    expect(new Set(labels.map(([, label]) => label)).size).toBe(labels.length);
  });
});
