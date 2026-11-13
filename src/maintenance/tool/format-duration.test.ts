import { describe, expect, it } from 'vitest';

import { formatDuration } from '@encryption/src/maintenance/tool/format-duration';

describe('formatDuration', () => {
  it('writes minutes and seconds, and hours only past one', () => {
    expect(formatDuration(0)).toBe('0:00');
    expect(formatDuration(65_999)).toBe('1:05');
    expect(formatDuration(750_000)).toBe('12:30');
    expect(formatDuration(3_723_000)).toBe('1:02:03');
  });
});
