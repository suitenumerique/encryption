import type { RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';

/** The latest version of a council's chain, null before its first one takes effect. */
export function rosterHead(chain: RosterVersionWire[]): RosterVersionWire | null {
  return chain.length > 0 ? chain[chain.length - 1] : null;
}
