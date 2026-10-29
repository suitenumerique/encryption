import { describe, expect, it } from 'vitest';

import type { CouncilRequestSummary } from '@encryption/src/ui/api/council-client';
import {
  REQUEST_STALLED_AFTER_MS,
  countByFilter,
  pendingActions,
  selectRequests,
  sortCouncils,
} from '@encryption/src/ui/components/council-custodian-logic';
import { custodianCouncil } from '@encryption/src/ui/testing/council-stories';
import { sampleRosterVersion } from '@encryption/src/ui/testing/fixtures';

const NOW = 1_800_000_000_000;
const DAY = 24 * 60 * 60 * 1000;

function request(overrides: Partial<CouncilRequestSummary> = {}): CouncilRequestSummary {
  return {
    id: crypto.randomUUID(),
    user_name: 'Ursula Roux',
    user_email: 'ursula.roux@numerique.gouv.fr',
    created_at_millis: NOW - DAY,
    expires_at_millis: NOW + 6 * DAY,
    stage: 'collecting',
    contributors: [],
    threshold: 2,
    my_contribution: 'none',
    can_contribute: false,
    ...overrides,
  };
}

describe('custodian space', () => {
  it('counts what waits on the custodian: requests they can act on, a change to sign, their part of a resharing', () => {
    expect(pendingActions(custodianCouncil())).toBe(0);
    expect(
      pendingActions(
        custodianCouncil({
          requests: [request({ can_contribute: true }), request(), request({ can_contribute: true })],
          proposal: { roster: sampleRosterVersion({ version: 2 }), quorum_missing: 1, pending_members: [], signed_by_me: false, may_sign: true },
          reshare: {
            session_id: 's',
            source_version: 1,
            target_version: 2,
            helper_slots: [1],
            i_am_helper: true,
            remaining_for_me: 3,
            remaining: 3,
          },
        })
      )
    ).toBe(4);
  });

  it('puts the councils with something waiting first', () => {
    const quiet = custodianCouncil({ council_id: 'a', label: 'A' });
    const busy = custodianCouncil({ council_id: 'z', label: 'Z', requests: [request({ can_contribute: true })] });

    expect(sortCouncils([quiet, busy]).map((c) => c.council_id)).toEqual(['z', 'a']);
  });

  it('lists the requests the custodian can act on first, then the closest to expiring', () => {
    const later = request({ id: 'later', expires_at_millis: NOW + 5 * DAY });
    const sooner = request({ id: 'sooner', expires_at_millis: NOW + DAY });
    const mine = request({ id: 'mine', can_contribute: true, expires_at_millis: NOW + 6 * DAY });

    expect(selectRequests([later, sooner, mine], 'all', '', NOW).map((r) => r.id)).toEqual(['mine', 'sooner', 'later']);
  });

  it('filters by name or email, ignoring case', () => {
    const victor = request({ id: 'v', user_name: 'Victor Lemaire', user_email: 'victor.lemaire@numerique.gouv.fr' });
    const ursula = request({ id: 'u' });

    expect(selectRequests([victor, ursula], 'all', 'LEMAIRE', NOW).map((r) => r.id)).toEqual(['v']);
    expect(selectRequests([victor, ursula], 'all', 'ursula.roux@', NOW).map((r) => r.id)).toEqual(['u']);
    expect(selectRequests([victor, ursula], 'all', '  ', NOW)).toHaveLength(2);
  });

  it('filters by stage, by what the custodian can do, and by requests open for long', () => {
    const requests = [
      request({ id: 'meeting', stage: 'awaiting_meeting', can_contribute: true }),
      request({ id: 'old', created_at_millis: NOW - REQUEST_STALLED_AFTER_MS }),
      request({ id: 'released', stage: 'released', created_at_millis: NOW - 5 * DAY }),
    ];

    expect(selectRequests(requests, 'to-handle', '', NOW).map((r) => r.id)).toEqual(['meeting']);
    expect(selectRequests(requests, 'awaiting_meeting', '', NOW).map((r) => r.id)).toEqual(['meeting']);
    // Released is past waiting on anyone: never counted as stalled.
    expect(selectRequests(requests, 'stalled', '', NOW).map((r) => r.id)).toEqual(['old']);
    expect(countByFilter(requests, NOW)).toMatchObject({ all: 3, 'to-handle': 1, collecting: 1, released: 1, cooldown: 0, stalled: 1 });
  });
});
