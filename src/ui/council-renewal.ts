import type { MnemonicLanguage } from '@encryption/src/crypto/mnemonic';
import type { CouncilEscrowBody, CouncilEscrowRecordWire, RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import type { CouncilForMe } from '@encryption/src/ui/api/council-client';
import type { Route } from '@encryption/src/ui/routes';
import type { CouncilEscrowCheck } from '@encryption/src/vault/operations/recovery-council';

// Screens on which a visit may renew the escrow. Never a flow that is creating,
// restoring or recovering the vault: those write their own escrow, or none yet.
const RENEWING_ROUTES: ReadonlySet<Route> = new Set(['settings', 'emergency-access', 'council-custodian', 'recipient-profile', 'verify-recipients']);

export function renewsOn(route: Route | null): boolean {
  return route !== null && RENEWING_ROUTES.has(route);
}

export interface CouncilRenewalDeps {
  fetchForMe: () => Promise<CouncilForMe>;
  checkEscrow: (record: CouncilEscrowRecordWire, chain: RosterVersionWire[]) => Promise<{ status: CouncilEscrowCheck; renewalDue?: boolean }>;
  createEscrow: (councilId: string, chain: RosterVersionWire[], lang: MnemonicLanguage, anchorHash: string) => Promise<CouncilEscrowBody>;
  enroll: (body: CouncilEscrowBody) => Promise<unknown>;
  lang: MnemonicLanguage;
}

export type CouncilRenewal = 'renewed' | 'not-due' | 'not-enrolled';

/**
 * A fresh emergency secret once a custodian who held a share of the current
 * one has left (architecture.md Appendix F.4): the user's vault splits it over
 * the current head, anchored on the version the user signed, and the server
 * replaces the old credential and capsules in the same write. Nothing happens
 * unless the vault verified the escrow and the chain: a tampered record or a
 * broken chain is left to the settings warning, never re-armed onto.
 */
export async function renewCouncilEscrowIfDue(deps: CouncilRenewalDeps): Promise<CouncilRenewal> {
  const { council, escrow } = await deps.fetchForMe();

  if (!council || !escrow || !escrow.vault_active || escrow.health.status === 'lost' || escrow.record.council_id !== council.council_id) {
    return 'not-enrolled';
  }

  const check = await deps.checkEscrow(escrow.record, council.chain);
  if (check.status !== 'ok' || !check.renewalDue) return 'not-due';

  await deps.enroll(await deps.createEscrow(council.council_id, council.chain, deps.lang, escrow.record.roster_hash));

  return 'renewed';
}

// A membership rarely changes, and a departure costs nothing until `k` former
// holders collude: one check a day per user is plenty.
export const COUNCIL_RENEWAL_INTERVAL_MS = 24 * 60 * 60 * 1000;

const lastCheckKey = (userId: string) => `encryption:council-renewal-checked:${userId}`;

/**
 * Whether this browser checked the user's escrow less than a day ago. Storage
 * that is missing or refuses access (private browsing) never blocks a check.
 */
export function checkedRecently(userId: string, now: number, storage: Pick<Storage, 'getItem'> | null): boolean {
  try {
    const last = Number(storage?.getItem(lastCheckKey(userId)));

    return Number.isFinite(last) && last > 0 && now - last < COUNCIL_RENEWAL_INTERVAL_MS && last <= now;
  } catch {
    return false;
  }
}

export function rememberCheck(userId: string, now: number, storage: Pick<Storage, 'setItem'> | null): void {
  try {
    storage?.setItem(lastCheckKey(userId), String(now));
  } catch {
    // Not remembered: the next visit checks again.
  }
}
