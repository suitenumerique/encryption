/**
 * A council's live recovery requests as one of its custodians sees them:
 * judged, filtered, searched, counted, sorted and paged by Postgres, so the
 * custodian space never loads a whole council's requests.
 *
 * The stage computed here is `requestStage` (council-requests-core.ts) written
 * in SQL: only contributions from a custodian still in the head with the key
 * they signed with count.
 */
import { z } from 'zod';

import { Prisma } from '@encryption/src/generated/prisma/client';
import { prisma } from '@encryption/src/prisma/client';
import { type RosterVersionRow, rawTable } from '@encryption/src/server/council-core';
import { type RequestStage, settleRequest } from '@encryption/src/server/council-requests-core';
import { userFullName } from '@encryption/src/server/user-name';
import { REQUEST_FILTERS, type RequestFilter } from '@encryption/src/shared/council-request-filters';

export const RequestFilterSchema = z.enum(REQUEST_FILTERS);

// Past this age a request still open has likely stalled: worth a word in the council.
export const REQUEST_STALLED_AFTER_MS = 3 * 24 * 60 * 60 * 1000;

type HeadMember = RosterVersionRow['members'][number];

// Stored timestamps are UTC without a zone: compare with UTC values of the same type.
const at = (millis: number) => Prisma.sql`${new Date(millis).toISOString()}::timestamp(3)`;

/** Requests past their expiry are settled first, so closing them still frees what a resharing holds back for them. */
async function settleExpired(councilId: string, nowMs: number): Promise<void> {
  const stale = await prisma.councilRequest.findMany({
    where: { councilId, status: { in: ['open', 'released'] }, expiresAt: { lte: new Date(nowMs) } },
    select: { id: true },
  });
  for (const { id } of stale) await settleRequest(id, nowMs);
}

/** Every live request of the council, with its stage and what this custodian can do, as a CTE named `judged`. */
function judged(councilId: string, head: RosterVersionRow, me: HeadMember, nowMs: number): Prisma.Sql {
  const members = Prisma.join(head.members.map((m) => Prisma.sql`(${m.slot}::int, ${m.identityId}::uuid)`));
  const counted = Prisma.sql`
    FROM ${rawTable('council_contributions')} c
    JOIN head h ON h.slot = c.slot AND h.identity_id = c.custodian_identity_id
    WHERE c.request_id = r.id`;

  return Prisma.sql`
    WITH head (slot, identity_id) AS (VALUES ${members}),
    facts AS (
      SELECT r.id, r.user_id, r.status, r.created_at, r.expires_at, r.release_not_before, e.threshold,
        u.first_name, u.last_name, u.email,
        (SELECT count(*) ${counted})::int AS counted,
        EXISTS (SELECT 1 ${counted} AND c.in_person) AS met,
        EXISTS (SELECT 1 ${counted} AND c.slot = ${me.slot}) AS mine,
        EXISTS (
          SELECT 1 FROM ${rawTable('council_capsules')} k
          WHERE k.escrow_id = e.id AND k.slot = ${me.slot} AND k.generation = e.generation
            AND k.identity_id = ${me.identityId}::uuid AND NOT k.invalid
        ) AS holds_part
      FROM ${rawTable('council_requests')} r
      JOIN ${rawTable('council_escrows')} e ON e.id = r.escrow_id
      JOIN ${rawTable('users')} u ON u.id = r.user_id
      WHERE r.council_id = ${councilId} AND r.status IN ('open', 'released') AND r.expires_at > ${at(nowMs)}
    ),
    staged AS (
      SELECT *,
        CASE
          WHEN status = 'released' THEN 'released'
          WHEN NOT met THEN 'awaiting_meeting'
          WHEN counted >= threshold THEN CASE WHEN release_not_before <= ${at(nowMs)} THEN 'released' ELSE 'cooldown' END
          ELSE 'collecting'
        END AS stage
      FROM facts
    ),
    judged AS (
      SELECT *,
        (NOT mine AND user_id <> ${me.userId}::uuid AND holds_part AND stage IN ('collecting', 'awaiting_meeting')) AS can_contribute,
        (stage IN ('collecting', 'awaiting_meeting') AND created_at <= ${at(nowMs - REQUEST_STALLED_AFTER_MS)}) AS stalled
      FROM staged
    )`;
}

function filterCondition(filter: RequestFilter): Prisma.Sql {
  switch (filter) {
    case 'all':
      return Prisma.sql`TRUE`;
    case 'to-handle':
      return Prisma.sql`can_contribute`;
    case 'stalled':
      return Prisma.sql`stalled`;
    default:
      return Prisma.sql`stage = ${filter}`;
  }
}

function searchCondition(query: string): Prisma.Sql {
  const needle = query.trim();
  if (!needle) return Prisma.sql`TRUE`;

  const pattern = `%${needle.replace(/[\\%_]/g, '\\$&')}%`;

  return Prisma.sql`(concat_ws(' ', first_name, last_name) ILIKE ${pattern} OR email ILIKE ${pattern})`;
}

/** How many live requests each filter of the menu holds, before any search. */
export async function custodianRequestCounts(
  councilId: string,
  head: RosterVersionRow,
  me: HeadMember,
  nowMs: number
): Promise<Record<RequestFilter, number>> {
  await settleExpired(councilId, nowMs);

  const columns = Prisma.join(REQUEST_FILTERS.map((f) => Prisma.sql`(count(*) FILTER (WHERE ${filterCondition(f)}))::int`));
  const [row] = await prisma.$queryRaw<
    Array<{ counts: number[] }>
  >`${judged(councilId, head, me, nowMs)} SELECT ARRAY[${columns}] AS counts FROM judged`;

  return Object.fromEntries(REQUEST_FILTERS.map((f, i) => [f, row.counts[i]])) as Record<RequestFilter, number>;
}

interface PageRow {
  id: string;
  first_name: string | null;
  last_name: string | null;
  email: string;
  created_at: Date;
  expires_at: Date;
  threshold: number;
  stage: RequestStage;
  can_contribute: boolean;
  holds_part: boolean;
  total: number;
}

/** One page of the requests matching the filter and the search: those the custodian can act on first, then the closest to expiring. */
export async function custodianRequestPage(
  councilId: string,
  head: RosterVersionRow,
  me: HeadMember,
  nowMs: number,
  select: { filter: RequestFilter; query: string; page: number; pageSize: number }
) {
  await settleExpired(councilId, nowMs);

  const rows = await prisma.$queryRaw<PageRow[]>`${judged(councilId, head, me, nowMs)}
    SELECT id, first_name, last_name, email, created_at, expires_at, threshold, stage, can_contribute, holds_part, (count(*) OVER ())::int AS total
    FROM judged
    WHERE ${filterCondition(select.filter)} AND ${searchCondition(select.query)}
    ORDER BY can_contribute DESC, expires_at ASC, id ASC
    LIMIT ${select.pageSize} OFFSET ${(select.page - 1) * select.pageSize}`;

  const headIdentity = new Map(head.members.map((m) => [m.slot, m.identityId]));
  const contributions = await prisma.councilContribution.findMany({
    where: { requestId: { in: rows.map((r) => r.id) } },
    select: { requestId: true, slot: true, inPerson: true, custodianIdentityId: true },
    orderBy: { createdAt: 'asc' },
  });

  const items = rows.map((row) => {
    const counted = contributions.filter((c) => c.requestId === row.id && headIdentity.get(c.slot) === c.custodianIdentityId);
    const mine = counted.find((c) => c.slot === me.slot);

    return {
      id: row.id,
      user_name: userFullName({ firstName: row.first_name, lastName: row.last_name }),
      user_email: row.email,
      created_at_millis: row.created_at.getTime(),
      expires_at_millis: row.expires_at.getTime(),
      stage: row.stage,
      contributors: counted.map((c) => {
        const member = head.members.find((m) => m.slot === c.slot)!;
        return { slot: c.slot, name: userFullName(member.user) ?? member.user.email, in_person: c.inPerson };
      }),
      // How many parts release it: the escrow's own threshold, which a later version may not share.
      threshold: row.threshold,
      my_contribution: mine ? (mine.inPerson ? ('in_person' as const) : ('remote' as const)) : ('none' as const),
      can_contribute: row.can_contribute,
      holds_part: row.holds_part,
    };
  });

  return { items, total: rows[0]?.total ?? (select.page > 1 ? await countMatching(councilId, head, me, nowMs, select) : 0) };
}

/** The total when the page asked for is past the last one (no row to carry it). */
async function countMatching(
  councilId: string,
  head: RosterVersionRow,
  me: HeadMember,
  nowMs: number,
  select: { filter: RequestFilter; query: string }
) {
  const [row] = await prisma.$queryRaw<Array<{ total: number }>>`${judged(councilId, head, me, nowMs)}
    SELECT count(*)::int AS total FROM judged WHERE ${filterCondition(select.filter)} AND ${searchCondition(select.query)}`;

  return row.total;
}
