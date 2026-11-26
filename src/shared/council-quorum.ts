// A council's size and threshold, wherever one is checked: the configuration,
// the wire schemas and every vault verifying a roster version. At least one
// custodian more than the threshold, so one departure never blocks a recovery.
export const COUNCIL_MIN_MEMBERS = 2;
// Beyond a dozen, coordinating a recovery stops being realistic, and every
// enrolled user carries one capsule per custodian.
export const COUNCIL_MAX_MEMBERS = 12;

/** Whether `threshold` of `members` custodians is a council this code accepts. */
export function councilSizeAllowed(members: number, threshold: number): boolean {
  return (
    Number.isInteger(members) &&
    Number.isInteger(threshold) &&
    members >= COUNCIL_MIN_MEMBERS &&
    members <= COUNCIL_MAX_MEMBERS &&
    threshold >= 1 &&
    threshold <= members - 1
  );
}

/**
 * Signatures of the previous roster version a membership change needs: a strict
 * majority of its members, and never fewer than its threshold. A recovery
 * touches one person, a change every user's future shares, hence the majority
 * on top of `k`. Shared by the chain verification, the server's progress count
 * and the screen that asks for signatures, like `genesisPeer`.
 */
export function changeQuorum(previous: { threshold: number; members: readonly unknown[] }): number {
  return Math.max(previous.threshold, Math.floor(previous.members.length / 2) + 1);
}

/**
 * The member a custodian checks before signing version 1: the next one by slot,
 * the last checking the first. Every member checks one other and is checked by
 * one other, so a key the server slipped in anywhere falls to a real custodian's
 * check, at one check per person instead of one per pair.
 */
export function genesisPeer<T extends { slot: number; userId: string }>(members: T[], userId: string): T | null {
  const sorted = [...members].sort((a, b) => a.slot - b.slot);
  const index = sorted.findIndex((m) => m.userId === userId);
  if (index === -1 || sorted.length < 2) return null;

  return sorted[(index + 1) % sorted.length];
}
