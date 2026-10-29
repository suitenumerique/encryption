import type { RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import type { CouncilRequestSummary, CustodianCouncil } from '@encryption/src/ui/api/council-client';

/** What waits on this custodian in one council: requests they can act on, a change to sign, their part of a resharing. */
export function pendingActions(council: CustodianCouncil): number {
  const requests = council.requests.filter((r) => r.can_contribute).length;
  const sign = council.proposal?.may_sign && !council.proposal.signed_by_me ? 1 : 0;
  const reshare = council.reshare?.i_am_helper && council.reshare.remaining_for_me > 0 ? 1 : 0;

  return requests + sign + reshare;
}

/** The councils with something waiting first, so the one that needs the custodian is never lost in the list. */
export function sortCouncils(councils: CustodianCouncil[]): CustodianCouncil[] {
  return [...councils].sort((a, b) => pendingActions(b) - pendingActions(a) || a.label.localeCompare(b.label));
}

export const REQUESTS_PAGE_SIZE = 5;

// Past this age a request still open has likely stalled: worth a word in the council.
export const REQUEST_STALLED_AFTER_MS = 3 * 24 * 60 * 60 * 1000;

export const REQUEST_FILTERS = ['all', 'to-handle', 'awaiting_meeting', 'collecting', 'cooldown', 'released', 'stalled'] as const;
export type RequestFilter = (typeof REQUEST_FILTERS)[number];

function matchesFilter(request: CouncilRequestSummary, filter: RequestFilter, now: number): boolean {
  switch (filter) {
    case 'all':
      return true;
    case 'to-handle':
      return request.can_contribute;
    case 'stalled':
      return (request.stage === 'collecting' || request.stage === 'awaiting_meeting') && now - request.created_at_millis >= REQUEST_STALLED_AFTER_MS;
    default:
      return request.stage === filter;
  }
}

function matchesQuery(request: CouncilRequestSummary, query: string): boolean {
  const needle = query.trim().toLocaleLowerCase();
  if (!needle) return true;

  return [request.user_name ?? '', request.user_email].some((field) => field.toLocaleLowerCase().includes(needle));
}

/**
 * The requests a custodian sees, those they can act on first, then the ones
 * closest to expiring.
 */
export function selectRequests(requests: CouncilRequestSummary[], filter: RequestFilter, query: string, now: number): CouncilRequestSummary[] {
  return requests
    .filter((r) => matchesFilter(r, filter, now) && matchesQuery(r, query))
    .sort((a, b) => Number(b.can_contribute) - Number(a.can_contribute) || a.expires_at_millis - b.expires_at_millis);
}

export function countByFilter(requests: CouncilRequestSummary[], now: number): Record<RequestFilter, number> {
  return Object.fromEntries(REQUEST_FILTERS.map((f) => [f, requests.filter((r) => matchesFilter(r, f, now)).length])) as Record<
    RequestFilter,
    number
  >;
}

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
