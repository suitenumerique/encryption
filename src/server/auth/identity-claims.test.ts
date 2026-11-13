import { describe, expect, it, vi } from 'vitest';

import { isIncomplete, lastNameFromFullName, pickIdentity, requestedUserinfoClaims } from '@encryption/src/server/auth/identity-claims';

vi.mock('@encryption/src/server/env', () => ({
  env: {
    OIDC_CLAIMS_FIRST_NAME: ['given_name'],
    OIDC_CLAIMS_LAST_NAME: ['usual_name', 'family_name'],
    OIDC_CLAIMS_FULL_NAME: ['name'],
  },
}));

describe('pickIdentity', () => {
  it('reads given_name + usual_name and given_name + family_name alike', () => {
    expect(pickIdentity([{ given_name: 'Alice', usual_name: 'Martin', email: 'a@x.fr' }])).toMatchObject({ firstName: 'Alice', lastName: 'Martin' });
    expect(pickIdentity([{ given_name: 'Alice', family_name: 'Martin' }])).toMatchObject({ firstName: 'Alice', lastName: 'Martin' });
  });

  it('prefers the first candidate claim, and the ID token over userinfo', () => {
    const identity = pickIdentity([
      { given_name: 'From ID token' },
      { given_name: 'From userinfo', usual_name: 'Usual', family_name: 'Family', email: 'u@x.fr', email_verified: true },
    ]);

    expect(identity).toEqual({ firstName: 'From ID token', lastName: 'Usual', email: 'u@x.fr', emailVerified: true, locale: null });
  });

  it('derives the last name from the full name when there is none (only given_name + name)', () => {
    expect(pickIdentity([{ given_name: 'Jean', name: 'Jean DUPONT' }]).lastName).toBe('DUPONT');
  });

  it("never pairs one answer's address with another answer's verification flag", () => {
    const identity = pickIdentity([{ email: 'unverified@x.fr' }, { email: 'other@x.fr', email_verified: true }]);

    expect(identity).toMatchObject({ email: 'unverified@x.fr', emailVerified: false });
  });

  it('leaves what is missing as null', () => {
    expect(pickIdentity([{ name: 'Jean Dupont' }])).toMatchObject({ firstName: null, lastName: null, email: null });
  });
});

describe('lastNameFromFullName', () => {
  it('removes the first occurrence of the first name, whatever the case, and trims', () => {
    expect(lastNameFromFullName('Jean Dupont', 'Jean')).toBe('Dupont');
    expect(lastNameFromFullName('DUPONT jean', 'Jean')).toBe('DUPONT');
    expect(lastNameFromFullName('Jean-Pierre Jean', 'Jean')).toBe('-Pierre Jean');
  });

  it('keeps the full name when the first name is not in it', () => {
    expect(lastNameFromFullName('Martin Dupont', 'Alice')).toBe('Martin Dupont');
  });

  it('answers an empty last name when nothing is left', () => {
    expect(lastNameFromFullName('  Jean ', 'Jean')).toBe('');
  });
});

describe('isIncomplete', () => {
  it('asks userinfo while the email or a name is missing', () => {
    expect(isIncomplete(pickIdentity([{ sub: 'u' }]))).toBe(true);
    expect(isIncomplete(pickIdentity([{ email: 'a@x.fr', given_name: 'A' }]))).toBe(true);
    expect(isIncomplete(pickIdentity([{ email: 'a@x.fr', given_name: 'A', family_name: 'B' }]))).toBe(false);
  });
});

describe('requestedUserinfoClaims', () => {
  it('asks for the email and every configured name claim, the first name as essential', () => {
    expect(requestedUserinfoClaims()).toEqual({
      email: { essential: true },
      email_verified: null,
      locale: null,
      given_name: { essential: true },
      usual_name: null,
      family_name: null,
      name: null,
    });
  });
});
