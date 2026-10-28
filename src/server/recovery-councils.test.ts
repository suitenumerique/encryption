import { describe, expect, it } from 'vitest';

import { councilForEmail, councilWarnings, recoveryCouncilsSchema } from '@encryption/src/server/recovery-councils';

const custodian = (n: number) => ({ userId: `${n}`.repeat(8) + '-0000-4000-8000-000000000000', email: `c${n}@numerique.gouv.fr` });

const council = (overrides: Record<string, unknown> = {}) => ({
  id: 'dinum',
  label: 'Équipe sécurité DINUM',
  domains: ['numerique.gouv.fr'],
  custodians: [custodian(1), custodian(2), custodian(3), custodian(4)],
  threshold: 2,
  ...overrides,
});

describe('recoveryCouncilsSchema', () => {
  it('accepts a council and fills the defaults', () => {
    const [parsed] = recoveryCouncilsSchema.parse([council()]);

    expect(parsed.requestTtlDays).toBe(7);
    expect(parsed.cooldownMinutes).toBe(0);
  });

  it('wants between 2 and 12 custodians', () => {
    expect(recoveryCouncilsSchema.safeParse([council({ custodians: [custodian(1)], threshold: 1 })]).success).toBe(false);
    expect(recoveryCouncilsSchema.safeParse([council({ custodians: [custodian(1), custodian(2)], threshold: 1 })]).success).toBe(true);

    const thirteen = Array.from({ length: 13 }, (_, i) => ({ userId: crypto.randomUUID(), email: `c${i}@numerique.gouv.fr` }));
    expect(recoveryCouncilsSchema.safeParse([council({ custodians: thirteen, threshold: 2 })]).success).toBe(false);
    expect(recoveryCouncilsSchema.safeParse([council({ custodians: thirteen.slice(0, 12), threshold: 11 })]).success).toBe(true);
  });

  // n out of n would make one absence block every recovery.
  it('wants one custodian more than the threshold, and a threshold of at least 1', () => {
    expect(recoveryCouncilsSchema.safeParse([council({ threshold: 4 })]).success).toBe(false);
    expect(recoveryCouncilsSchema.safeParse([council({ threshold: 3 })]).success).toBe(true);
    expect(recoveryCouncilsSchema.safeParse([council({ threshold: 0 })]).success).toBe(false);
  });

  it('refuses a custodian or an email listed twice, a council id used twice and a domain claimed twice', () => {
    expect(recoveryCouncilsSchema.safeParse([council({ custodians: [custodian(1), custodian(1), custodian(2)] })]).success).toBe(false);
    expect(
      recoveryCouncilsSchema.safeParse([council({ custodians: [custodian(1), { ...custodian(2), email: custodian(1).email }, custodian(3)] })])
        .success
    ).toBe(false);
    expect(recoveryCouncilsSchema.safeParse([council(), council({ domains: ['interieur.gouv.fr'] })]).success).toBe(false);
    expect(recoveryCouncilsSchema.safeParse([council(), council({ id: 'other' })]).success).toBe(false);
  });

  it('refuses an id that is not a simple slug', () => {
    expect(recoveryCouncilsSchema.safeParse([council({ id: 'DINUM council' })]).success).toBe(false);
  });
});

describe('councilForEmail', () => {
  it('matches users by email domain like maintenance keys', () => {
    const councils = recoveryCouncilsSchema.parse([council(), council({ id: 'rest', domains: ['*'] })]);

    expect(councilForEmail(councils, 'alice@numerique.gouv.fr')?.id).toBe('dinum');
    expect(councilForEmail(councils, 'bob@equipe.numerique.gouv.fr')?.id).toBe('dinum');
    expect(councilForEmail(councils, 'carol@interieur.gouv.fr')?.id).toBe('rest');
  });
});

describe('councilWarnings', () => {
  it('flags a threshold of 1 and a margin of 1', () => {
    const [tight] = recoveryCouncilsSchema.parse([council({ custodians: [custodian(1), custodian(2)], threshold: 1 })]);
    const [comfortable] = recoveryCouncilsSchema.parse([council()]);

    expect(councilWarnings([tight])).toHaveLength(2);
    expect(councilWarnings([comfortable])).toEqual([]);
  });
});
