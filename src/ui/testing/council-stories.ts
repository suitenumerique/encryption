import { MSG_VAULT_COUNCIL_CHECK_ESCROW } from '@encryption/src/shared/constants';
import type { CouncilForMe, CustodianCouncil } from '@encryption/src/ui/api/council-client';
import { sampleCouncilEscrowRecord, sampleRosterVersion } from '@encryption/src/ui/testing/fixtures';
import { defaultVaultRequest } from '@encryption/src/ui/testing/mock-encryption';

// Shared states of the recovery council stories: what the server answers for a
// user (for-me) and for a custodian (mine), built from the same sample roster.

export const COUNCIL_LABEL = 'Équipe sécurité DINUM';

export function forMe(overrides: { escrow?: Partial<NonNullable<CouncilForMe['escrow']>> | null; configured?: boolean } = {}): CouncilForMe {
  return {
    council: { council_id: 'dinum', label: COUNCIL_LABEL, configured: overrides.configured ?? true, chain: [sampleRosterVersion()] },
    escrow:
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
          },
  };
}

/** The vault stub, answering the escrow audit with `status`. */
export function vaultCheckingEscrow(status: 'ok' | 'tampered' | 'chain-broken') {
  return async (type: string, payload?: unknown) =>
    type === MSG_VAULT_COUNCIL_CHECK_ESCROW ? { status, headFingerprint: null } : defaultVaultRequest(type, payload);
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
    requests: [],
    reshare: null,
    shares_to_check: 0,
    faulty_reshares: [],
    ...overrides,
  };
}
