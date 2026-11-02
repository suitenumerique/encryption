import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { domainGroupForEmail, emailDomainSchema, jsonEnvironmentValue, refineDomainGroups } from '@encryption/src/server/email-domain-groups';

const groups = z.array(z.object({ name: z.string(), domains: z.array(emailDomainSchema) })).superRefine(refineDomainGroups);

describe('domainGroupForEmail', () => {
  const entries = groups.parse([
    { name: 'ministry', domains: ['agriculture.gouv.fr'] },
    { name: 'team', domains: ['forets.agriculture.gouv.fr'] },
    { name: 'rest', domains: ['*'] },
  ]);

  it('picks the longest listed domain on a label boundary, else the * entry', () => {
    expect(domainGroupForEmail(entries, 'alice@agriculture.gouv.fr')?.name).toBe('ministry');
    expect(domainGroupForEmail(entries, 'bob@monequipe.agriculture.gouv.fr')?.name).toBe('ministry');
    expect(domainGroupForEmail(entries, 'carol@Sylve.FORETS.agriculture.gouv.fr')?.name).toBe('team');
    expect(domainGroupForEmail(entries, 'dan@fauxagriculture.gouv.fr')?.name).toBe('rest');
  });

  it('answers null when nothing covers the email', () => {
    expect(domainGroupForEmail(entries.slice(0, 2), 'eve@interieur.gouv.fr')).toBeNull();
    expect(domainGroupForEmail([], 'eve@interieur.gouv.fr')).toBeNull();
  });
});

describe('email domain groups', () => {
  it('lowercases domains and refuses one listed twice', () => {
    expect(groups.parse([{ name: 'a', domains: ['Agriculture.GOUV.fr'] }])[0].domains).toEqual(['agriculture.gouv.fr']);
    expect(
      groups.safeParse([
        { name: 'a', domains: ['agriculture.gouv.fr'] },
        { name: 'b', domains: ['AGRICULTURE.gouv.fr'] },
      ]).success
    ).toBe(false);
    expect(groups.safeParse([{ name: 'a', domains: ['not a domain'] }]).success).toBe(false);
  });

  it('reads a JSON variable, unset or empty meaning off', () => {
    const schema = z.preprocess(jsonEnvironmentValue('must be JSON'), z.array(z.number()).optional());

    expect(schema.parse(undefined)).toBeUndefined();
    expect(schema.parse('')).toBeUndefined();
    expect(schema.parse('[1,2]')).toEqual([1, 2]);
    expect(schema.safeParse('[1,').success).toBe(false);
  });
});
