import { describe, expect, it } from 'vitest';

import { resolveThemeName } from '@encryption/src/ui/theme';

describe('resolveThemeName', () => {
  it('maps the products theme names to the design system ones', () => {
    expect(resolveThemeName('dsfr')).toBe('dsfr-light');
    expect(resolveThemeName('anct')).toBe('anct-light');
    expect(resolveThemeName('light')).toBe('default');
  });

  it('keeps a name the design system already knows', () => {
    expect(resolveThemeName('dsfr-dark')).toBe('dsfr-dark');
    expect(resolveThemeName('dark')).toBe('dark');
  });

  it('falls back to the default theme', () => {
    expect(resolveThemeName(null)).toBe('default');
    expect(resolveThemeName('')).toBe('default');
  });
});
