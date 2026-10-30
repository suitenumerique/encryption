import { describe, expect, it } from 'vitest';

import {
  REQUEST_STALLED_AFTER_MS,
  type SelectableRequest,
  countByFilter,
  paginate,
  selectRequests,
} from '@encryption/src/server/council-requests-select';

const NOW = 1_800_000_000_000;
const DAY = 24 * 60 * 60 * 1000;

function view(
  id: string,
  overrides: {
    stage?: SelectableRequest['stage'];
    canContribute?: boolean;
    createdAt?: number;
    expiresAt?: number;
    name?: string;
    email?: string;
  } = {}
) {
  return {
    row: {
      id,
      createdAt: new Date(overrides.createdAt ?? NOW - DAY),
      expiresAt: new Date(overrides.expiresAt ?? NOW + 6 * DAY),
      user: {
        firstName: overrides.name?.split(' ')[0] ?? 'Ursula',
        lastName: overrides.name?.split(' ')[1] ?? 'Roux',
        email: overrides.email ?? 'ursula.roux@numerique.gouv.fr',
      },
    },
    stage: overrides.stage ?? 'collecting',
    canContribute: overrides.canContribute ?? false,
  };
}

const ids = (views: Array<SelectableRequest & { row: { id: string } }>) => views.map((v) => v.row.id);

describe('a council’s requests for a custodian', () => {
  it('lists the requests the custodian can act on first, then the closest to expiring', () => {
    const later = view('later', { expiresAt: NOW + 5 * DAY });
    const sooner = view('sooner', { expiresAt: NOW + DAY });
    const mine = view('mine', { canContribute: true, expiresAt: NOW + 6 * DAY });

    expect(ids(selectRequests([later, sooner, mine], 'all', '', NOW))).toEqual(['mine', 'sooner', 'later']);
  });

  it('searches by name or email, ignoring case', () => {
    const victor = view('v', { name: 'Victor Lemaire', email: 'victor.lemaire@numerique.gouv.fr' });
    const ursula = view('u');

    expect(ids(selectRequests([victor, ursula], 'all', 'LEMAIRE', NOW))).toEqual(['v']);
    expect(ids(selectRequests([victor, ursula], 'all', 'ursula.roux@', NOW))).toEqual(['u']);
    expect(selectRequests([victor, ursula], 'all', '  ', NOW)).toHaveLength(2);
  });

  it('filters by stage, by what the custodian can do, and by requests open for long', () => {
    const views = [
      view('meeting', { stage: 'awaiting_meeting', canContribute: true }),
      view('old', { createdAt: NOW - REQUEST_STALLED_AFTER_MS }),
      view('released', { stage: 'released', createdAt: NOW - 5 * DAY }),
    ];

    expect(ids(selectRequests(views, 'to-handle', '', NOW))).toEqual(['meeting']);
    expect(ids(selectRequests(views, 'awaiting_meeting', '', NOW))).toEqual(['meeting']);
    // Released is past waiting on anyone: never counted as stalled.
    expect(ids(selectRequests(views, 'stalled', '', NOW))).toEqual(['old']);
    expect(countByFilter(views, NOW)).toMatchObject({ all: 3, 'to-handle': 1, collecting: 1, released: 1, cooldown: 0, stalled: 1 });
  });

  it('cuts pages numbered from 1', () => {
    expect(paginate([1, 2, 3, 4, 5, 6, 7], 5, 1)).toEqual([1, 2, 3, 4, 5]);
    expect(paginate([1, 2, 3, 4, 5, 6, 7], 5, 2)).toEqual([6, 7]);
    expect(paginate([1, 2, 3], 5, 2)).toEqual([]);
  });
});
