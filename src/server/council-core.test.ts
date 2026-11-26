import { describe, expect, it, vi } from 'vitest';

import { type RosterVersionRow, absentAmong, escrowHealth, headHealth } from '@encryption/src/server/council-core';

vi.mock('@encryption/src/server/env', () => ({ env: {} }));
vi.mock('@encryption/src/prisma/client', () => ({ prisma: {} }));

// Four custodians, threshold 2: a margin of two.
const head = {
  id: 'head',
  threshold: 2,
  members: [1, 2, 3, 4].map((slot) => ({ slot, userId: `user-${slot}`, identityId: `identity-${slot}` })),
} as unknown as RosterVersionRow;

const escrow = {
  rosterVersionId: 'head',
  threshold: 2,
  generation: 1,
  capsules: [1, 2, 3, 4].map((slot) => ({ slot, identityId: `identity-${slot}`, generation: 1, invalid: false })),
};

const allActive = new Set(['identity-1', 'identity-2', 'identity-3', 'identity-4']);

describe('escrowHealth', () => {
  it('is ok with a margin, at risk without one, lost below the threshold', () => {
    expect(escrowHealth(escrow, head, allActive).status).toBe('ok');
    expect(escrowHealth(escrow, head, new Set(['identity-1', 'identity-2', 'identity-3'])).status).toBe('ok');
    expect(escrowHealth(escrow, head, new Set(['identity-1', 'identity-2'])).status).toBe('at-risk');
    expect(escrowHealth(escrow, head, new Set(['identity-1'])).status).toBe('lost');
  });

  // An absent custodian may come back: their share is never lost, only the margin.
  it('counts an absent custodian’s share as live but not toward the margin', () => {
    const health = escrowHealth(escrow, head, allActive, new Set(['user-1', 'user-2']));

    expect(health).toMatchObject({ live: 4, absent: 2, status: 'at-risk' });
    expect(escrowHealth(escrow, head, new Set(['identity-1', 'identity-2']), new Set(['user-1', 'user-2'])).status).toBe('at-risk');
    expect(escrowHealth(escrow, head, new Set(['identity-1']), new Set(['user-1'])).status).toBe('lost');
  });

  it('ignores the absence of a custodian whose share no longer counts', () => {
    expect(escrowHealth(escrow, head, new Set(['identity-1', 'identity-2', 'identity-3']), new Set(['user-4'])).absent).toBe(0);
  });
});

describe('headHealth', () => {
  it('judges the margin left for people joining from now on', () => {
    expect(headHealth(head, allActive, new Set())).toBe('ok');
    expect(headHealth(head, allActive, new Set(['user-3']))).toBe('ok');
    expect(headHealth(head, allActive, new Set(['user-3', 'user-4']))).toBe('at-risk');
    expect(headHealth(head, new Set(['identity-1']), new Set())).toBe('lost');
  });
});

describe('absentAmong', () => {
  const day = 24 * 60 * 60 * 1000;
  const now = Date.UTC(2026, 10, 2);

  it('names the users whose last sign-in is older than the given days', () => {
    const lastSignIns = new Map([
      ['recent', now - 10 * day],
      ['old', now - 91 * day],
    ]);

    expect([...absentAmong(lastSignIns, ['recent', 'old', 'unknown'], 90, now)]).toEqual(['old']);
  });
});
