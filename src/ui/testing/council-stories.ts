import { MSG_VAULT_COUNCIL_CHECK_ESCROW } from '@encryption/src/shared/constants';
import { REQUEST_FILTERS, type RequestFilter } from '@encryption/src/shared/council-request-filters';
import type { CouncilForMe, CouncilRequestSummary, CustodianCouncil } from '@encryption/src/ui/api/council-client';
import { handleGetApiCouncilsByCouncilIdRequests } from '@encryption/src/ui/api/generated/msw.gen';
import { sampleCouncilEscrowRecord, sampleCouncilFingerprint, sampleRosterVersion } from '@encryption/src/ui/testing/fixtures';
import { defaultVaultRequest } from '@encryption/src/ui/testing/mock-encryption';

// Shared states of the recovery council stories: what the server answers for a
// user (for-me) and for a custodian (mine), built from the same sample roster.

export const COUNCIL_LABEL = 'Équipe sécurité DINUM';

export function forMe(
  overrides: {
    escrow?: Partial<NonNullable<CouncilForMe['escrow']>> | null;
    configured?: boolean;
    vaults?: CouncilForMe['vaults'];
    activeVaultCreatedAtMillis?: number | null;
  } = {}
): CouncilForMe {
  const escrow: CouncilForMe['escrow'] =
    overrides.escrow === null || overrides.escrow === undefined
      ? null
      : {
          id: '7f1c2b3a-0000-4000-8000-000000000001',
          council_id: 'dinum',
          vault_active: true,
          generation: 1,
          current_version: 1,
          record: sampleCouncilEscrowRecord,
          health: { live: 4, threshold: 2, status: 'ok', outdated: false },
          ...overrides.escrow,
        };

  return {
    council: { council_id: 'dinum', label: COUNCIL_LABEL, configured: overrides.configured ?? true, chain: [sampleRosterVersion()] },
    escrow,
    active_vault_created_at_millis: overrides.activeVaultCreatedAtMillis === undefined ? Date.UTC(2026, 0, 12) : overrides.activeVaultCreatedAtMillis,
    // By default the one escrow's vault, unless too few custodians remain.
    vaults:
      overrides.vaults ??
      (escrow && escrow.health.status !== 'lost'
        ? [{ escrow_id: escrow.id, active: escrow.vault_active, created_at_millis: Date.UTC(2026, 0, 12), disabled_at_millis: null }]
        : []),
  };
}

/** The vault stub, answering the escrow audit with `status`, and whether the user verified the council. */
export function vaultCheckingEscrow(status: 'ok' | 'tampered' | 'chain-broken', verified = false) {
  return async (type: string, payload?: unknown) =>
    type === MSG_VAULT_COUNCIL_CHECK_ESCROW
      ? { status, renewalDue: false, council: status === 'ok' ? { fingerprint: sampleCouncilFingerprint, verified } : null }
      : defaultVaultRequest(type, payload);
}

export function custodianCouncil(overrides: Partial<CustodianCouncil> = {}): CustodianCouncil {
  return {
    council_id: 'dinum',
    label: COUNCIL_LABEL,
    role: 'custodian',
    configured: true,
    my_slot: 1,
    chain: [sampleRosterVersion()],
    proposal: null,
    blocked: [],
    health: { escrows: 128, ok: 128, at_risk: 0, lost: 0, outdated: [] },
    requests_count: 0,
    requests_to_handle: 0,
    reshare: null,
    shares_to_check: 0,
    faulty_reshares: [],
    ...overrides,
  };
}

/** What `/api/councils/mine` says of a council holding `requests`. */
export function requestCounts(requests: CouncilRequestSummary[]): Pick<CustodianCouncil, 'requests_count' | 'requests_to_handle'> {
  return { requests_count: requests.length, requests_to_handle: requests.filter((r) => r.can_contribute).length };
}

const STALLED_AFTER_MS = 3 * 24 * 60 * 60 * 1000;

function matches(request: CouncilRequestSummary, filter: RequestFilter, now: number): boolean {
  if (filter === 'all') return true;
  if (filter === 'to-handle') return request.can_contribute;
  if (filter === 'stalled')
    return (request.stage === 'collecting' || request.stage === 'awaiting_meeting') && now - request.created_at_millis >= STALLED_AFTER_MS;

  return request.stage === filter;
}

/** A stand-in for the server's paged request list over `requests`: same filters, search, order and pages. */
export function councilRequestsHandler(requests: CouncilRequestSummary[]) {
  return handleGetApiCouncilsByCouncilIdRequests(({ request }) => {
    const params = new URL(request.url).searchParams;
    const now = Date.now();
    const filter = (params.get('filter') ?? 'all') as RequestFilter;
    const needle = (params.get('query') ?? '').trim().toLocaleLowerCase();
    const page = Number(params.get('page') ?? 1);
    const pageSize = Number(params.get('page_size') ?? 5);

    const selected = requests
      .filter((r) => matches(r, filter, now) && [r.user_name ?? '', r.user_email].some((f) => f.toLocaleLowerCase().includes(needle)))
      .sort((a, b) => Number(b.can_contribute) - Number(a.can_contribute) || a.expires_at_millis - b.expires_at_millis);

    return Response.json({
      items: selected.slice((page - 1) * pageSize, page * pageSize),
      total_count: selected.length,
      counts: Object.fromEntries(REQUEST_FILTERS.map((f) => [f, requests.filter((r) => matches(r, f, now)).length])),
    });
  });
}
