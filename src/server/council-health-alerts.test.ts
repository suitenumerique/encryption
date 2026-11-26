import { describe, expect, it, vi } from 'vitest';

import { absenceReminderDue, healthAlertDue } from '@encryption/src/server/council-health-alerts';

vi.mock('@encryption/src/server/env', () => ({ env: {} }));
vi.mock('@encryption/src/prisma/client', () => ({ prisma: {} }));

describe('healthAlertDue', () => {
  it('tells the custodians only when the health gets worse than what they were told', () => {
    expect(healthAlertDue(null, 'ok')).toBe(false);
    expect(healthAlertDue(null, 'at-risk')).toBe(true);
    expect(healthAlertDue('ok', 'lost')).toBe(true);
    expect(healthAlertDue('at-risk', 'lost')).toBe(true);
    expect(healthAlertDue('at-risk', 'at-risk')).toBe(false);
    expect(healthAlertDue('lost', 'at-risk')).toBe(false);
  });

  it('tells them when nobody can join, below any loss of margin', () => {
    expect(healthAlertDue('ok', 'blocked')).toBe(true);
    expect(healthAlertDue('blocked', 'blocked')).toBe(false);
    expect(healthAlertDue('blocked', 'at-risk')).toBe(true);
    expect(healthAlertDue('at-risk', 'blocked')).toBe(false);
  });

  it('treats an unknown stored value as ok', () => {
    expect(healthAlertDue('unknown', 'at-risk')).toBe(true);
  });
});

describe('absenceReminderDue', () => {
  it('asks once per absence: again only after a sign-in that ended the previous one', () => {
    expect(absenceReminderDue(null, 1_000)).toBe(true);
    expect(absenceReminderDue(2_000, 1_000)).toBe(false);
    expect(absenceReminderDue(2_000, 3_000)).toBe(true);
  });
});
