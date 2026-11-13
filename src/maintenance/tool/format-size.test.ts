import { describe, expect, it } from 'vitest';

import { formatSize } from '@encryption/src/maintenance/tool/format-size';

describe('formatSize', () => {
  it('names the unit, in the reader language', () => {
    expect(formatSize(830, 'en')).toBe('830 bytes');
    expect(formatSize(830, 'fr').replace(/\s/g, ' ')).toBe('830 octets');
    expect(formatSize(1234, 'en')).toBe('1.2 kB');
    expect(formatSize(5_600_000, 'en')).toBe('5.6 MB');
    expect(formatSize(1234, 'fr').replace(/\s/g, ' ')).toBe('1,2 ko');
  });
});
