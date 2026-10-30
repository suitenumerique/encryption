import { describe, expect, it } from 'vitest';

import { pendingActions, sortCouncils } from '@encryption/src/ui/components/council-custodian-logic';
import { custodianCouncil } from '@encryption/src/ui/testing/council-stories';
import { sampleRosterVersion } from '@encryption/src/ui/testing/fixtures';

describe('custodian space', () => {
  it('counts what waits on the custodian: requests they can act on, a change to sign, their part of a resharing', () => {
    expect(pendingActions(custodianCouncil())).toBe(0);
    expect(
      pendingActions(
        custodianCouncil({
          requests_count: 3,
          requests_to_handle: 2,
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
    const busy = custodianCouncil({ council_id: 'z', label: 'Z', requests_count: 1, requests_to_handle: 1 });

    expect(sortCouncils([quiet, busy]).map((c) => c.council_id)).toEqual(['z', 'a']);
  });
});
