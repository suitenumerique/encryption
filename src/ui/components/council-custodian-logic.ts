import type { RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import type { CustodianCouncil } from '@encryption/src/ui/api/council-client';

/** What waits on this custodian in one council: requests they can act on, a change to sign, their part of a resharing. */
export function pendingActions(council: CustodianCouncil): number {
  const requests = council.requests_to_handle;
  const sign = council.proposal?.may_sign && !council.proposal.signed_by_me ? 1 : 0;
  const reshare = council.reshare?.i_am_helper && council.reshare.remaining_for_me > 0 ? 1 : 0;

  return requests + sign + reshare;
}

/** The councils with something waiting first, so the one that needs the custodian is never lost in the list. */
export function sortCouncils(councils: CustodianCouncil[]): CustodianCouncil[] {
  return [...councils].sort((a, b) => pendingActions(b) - pendingActions(a) || a.label.localeCompare(b.label));
}

export const REQUESTS_PAGE_SIZE = 5;

/** Who a proposed version adds, removes, or names with another key, against the version in force. */
export function membershipChanges(head: RosterVersionWire, proposal: RosterVersionWire): { joining: string[]; leaving: string[]; newKey: string[] } {
  const name = (m: RosterVersionWire['members'][number]) => m.name ?? `#${m.slot}`;
  const before = new Map(head.members.map((m) => [m.user_id, m]));
  const after = new Set(proposal.members.map((m) => m.user_id));

  return {
    joining: proposal.members.filter((m) => !before.has(m.user_id)).map(name),
    leaving: head.members.filter((m) => !after.has(m.user_id)).map(name),
    newKey: proposal.members.filter((m) => before.has(m.user_id) && before.get(m.user_id)!.identity_public_key !== m.identity_public_key).map(name),
  };
}
