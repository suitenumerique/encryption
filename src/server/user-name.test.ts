import { describe, expect, it } from 'vitest';

import { userFullName, userLabel, userLabelWithEmail } from '@encryption/src/server/user-name';

describe('userFullName', () => {
  it('joins the first and last names', () => {
    expect(userFullName({ firstName: 'Alice', lastName: 'Martin' })).toBe('Alice Martin');
  });

  it('keeps the one name known', () => {
    expect(userFullName({ firstName: 'Alice', lastName: null })).toBe('Alice');
    expect(userFullName({ firstName: null, lastName: 'Martin' })).toBe('Martin');
  });

  it('is null when no name is known, blank ones included', () => {
    expect(userFullName({ firstName: null, lastName: null })).toBeNull();
    expect(userFullName({ firstName: ' ', lastName: '' })).toBeNull();
  });
});

describe('userLabel / userLabelWithEmail', () => {
  const alice = { firstName: 'Alice', lastName: 'Martin', email: 'alice@example.org' };
  const nameless = { firstName: null, lastName: null, email: 'bob@example.org' };

  it('names a user, with their address in brackets when asked', () => {
    expect(userLabel(alice)).toBe('Alice Martin');
    expect(userLabelWithEmail(alice)).toBe('Alice Martin (alice@example.org)');
  });

  it('falls back to the address alone when no name is known', () => {
    expect(userLabel(nameless)).toBe('bob@example.org');
    expect(userLabelWithEmail(nameless)).toBe('bob@example.org');
  });
});
