/**
 * A council's live recovery requests as its custodians see them: filtered,
 * searched, sorted and paged on the server, so the custodian space never
 * downloads a whole council's requests.
 */
import { z } from 'zod';

import { prisma } from '@encryption/src/prisma/client';
import type { RosterVersionRow } from '@encryption/src/server/council-core';
import { type RequestStage, requestStage, settleRequest } from '@encryption/src/server/council-requests-core';
import type { SelectableRequest } from '@encryption/src/server/council-requests-select';
import { userFullName } from '@encryption/src/server/user-name';
import { REQUEST_FILTERS } from '@encryption/src/shared/council-request-filters';

export const RequestFilterSchema = z.enum(REQUEST_FILTERS);

type HeadMember = RosterVersionRow['members'][number];

async function liveRequestRows(councilId: string, mySlot: number, nowMs: number) {
  return prisma.councilRequest.findMany({
    where: { escrow: { councilId }, status: { in: ['open', 'released'] }, expiresAt: { gt: new Date(nowMs) } },
    include: {
      user: { select: { firstName: true, lastName: true, email: true } },
      contributions: { select: { slot: true, inPerson: true, custodianIdentityId: true } },
      escrow: { select: { threshold: true, generation: true, capsules: { where: { slot: mySlot } } } },
    },
  });
}

type LiveRequestRow = Awaited<ReturnType<typeof liveRequestRows>>[number];

/** One request as the custodian at `me` sees it: what is pure arithmetic over the row, no write. */
export interface CustodianRequestView extends SelectableRequest {
  row: LiveRequestRow;
  stage: RequestStage;
  contributions: Array<{ slot: number; inPerson: boolean }>;
  mine: { inPerson: boolean } | null;
  canContribute: boolean;
}

/**
 * Every live request of the council, judged for one custodian. Requests past
 * their expiry are settled first, so closing them still frees what a resharing
 * holds back for them.
 */
export async function custodianRequestViews(
  councilId: string,
  head: RosterVersionRow,
  me: HeadMember,
  nowMs: number
): Promise<CustodianRequestView[]> {
  const stale = await prisma.councilRequest.findMany({
    where: { escrow: { councilId }, status: { in: ['open', 'released'] }, expiresAt: { lte: new Date(nowMs) } },
    select: { id: true },
  });
  for (const { id } of stale) await settleRequest(id, nowMs);

  return (await liveRequestRows(councilId, me.slot, nowMs)).map((row) => {
    // Only contributions from a custodian still in the head with the key they signed with count.
    const contributions = row.contributions
      .filter((c) => head.members.some((m) => m.slot === c.slot && m.identityId === c.custodianIdentityId))
      .map((c) => ({ slot: c.slot, inPerson: c.inPerson }));
    const stage = requestStage({ request: row, threshold: row.escrow.threshold, contributions }, nowMs);
    const mine = contributions.find((c) => c.slot === me.slot) ?? null;
    const myCapsule = row.escrow.capsules.find((c) => c.generation === row.escrow.generation && c.identityId === me.identityId && !c.invalid);

    return {
      row,
      stage,
      contributions,
      mine,
      canContribute: !mine && row.userId !== me.userId && myCapsule !== undefined && (stage === 'collecting' || stage === 'awaiting_meeting'),
    };
  });
}

export function requestSummaryWire(view: CustodianRequestView, head: RosterVersionRow) {
  return {
    id: view.row.id,
    user_name: userFullName(view.row.user),
    user_email: view.row.user.email,
    created_at_millis: view.row.createdAt.getTime(),
    expires_at_millis: view.row.expiresAt.getTime(),
    stage: view.stage,
    contributors: view.contributions.map((c) => {
      const member = head.members.find((m) => m.slot === c.slot);
      return { slot: c.slot, name: member ? (userFullName(member.user) ?? member.user.email) : `#${c.slot}`, in_person: c.inPerson };
    }),
    // How many parts release it: the escrow's own threshold, which a later version may not share.
    threshold: view.row.escrow.threshold,
    my_contribution: view.mine ? (view.mine.inPerson ? ('in_person' as const) : ('remote' as const)) : ('none' as const),
    can_contribute: view.canContribute,
  };
}
