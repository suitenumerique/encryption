/** How a custodian's request list is filtered, searched, ordered and paged: pure, over rows already judged. */
import type { RequestStage } from '@encryption/src/server/council-requests-core';
import { userFullName } from '@encryption/src/server/user-name';
import { REQUEST_FILTERS, type RequestFilter } from '@encryption/src/shared/council-request-filters';

// Past this age a request still open has likely stalled: worth a word in the council.
export const REQUEST_STALLED_AFTER_MS = 3 * 24 * 60 * 60 * 1000;

export interface SelectableRequest {
  row: { createdAt: Date; expiresAt: Date; user: { firstName: string | null; lastName: string | null; email: string } };
  stage: RequestStage;
  canContribute: boolean;
}

function matchesFilter(view: SelectableRequest, filter: RequestFilter, nowMs: number): boolean {
  switch (filter) {
    case 'all':
      return true;
    case 'to-handle':
      return view.canContribute;
    case 'stalled':
      return (view.stage === 'collecting' || view.stage === 'awaiting_meeting') && nowMs - view.row.createdAt.getTime() >= REQUEST_STALLED_AFTER_MS;
    default:
      return view.stage === filter;
  }
}

function matchesQuery(view: SelectableRequest, query: string): boolean {
  const needle = query.trim().toLocaleLowerCase();
  if (!needle) return true;

  return [userFullName(view.row.user) ?? '', view.row.user.email].some((field) => field.toLocaleLowerCase().includes(needle));
}

export function countByFilter(views: SelectableRequest[], nowMs: number): Record<RequestFilter, number> {
  return Object.fromEntries(REQUEST_FILTERS.map((f) => [f, views.filter((v) => matchesFilter(v, f, nowMs)).length])) as Record<RequestFilter, number>;
}

/** The requests a custodian asked for: those they can act on first, then the ones closest to expiring. */
export function selectRequests<T extends SelectableRequest>(views: T[], filter: RequestFilter, query: string, nowMs: number): T[] {
  return views
    .filter((v) => matchesFilter(v, filter, nowMs) && matchesQuery(v, query))
    .sort((a, b) => Number(b.canContribute) - Number(a.canContribute) || a.row.expiresAt.getTime() - b.row.expiresAt.getTime());
}

/** One page, numbered from 1. */
export function paginate<T>(items: T[], pageSize: number, page: number): T[] {
  return items.slice((page - 1) * pageSize, page * pageSize);
}
