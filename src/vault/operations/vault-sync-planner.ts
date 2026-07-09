/**
 * Pure decision logic for the sync engine, separated from all I/O so it can be
 * tested exhaustively. Given the server's state and the state after merging in
 * local changes, it works out exactly which items to push and the
 * last-known-revision each push must carry for the server's optimistic-
 * concurrency check.
 */
import { type PlainItem, stateToItems } from '@encryption/src/crypto/vault-items';
import type { VaultState } from '@encryption/src/crypto/vault-state';

export interface PushItem {
  item: PlainItem;
  /** The server's current revisionDate for this item, or null if it is new. */
  lastKnownRevisionDate: number | null;
}

/**
 * Items whose content differs from what the server holds. Immutable keys never
 * differ once present, so in practice this is the changed TOFU entries plus the
 * active pointer on a rotation. Comparing full JSON keeps it robust to any field
 * change, not just revisionDate.
 */
export function planPush(server: VaultState, merged: VaultState): PushItem[] {
  const serverById = new Map(stateToItems(server).map((i) => [i.id, i]));
  const pushes: PushItem[] = [];

  for (const item of stateToItems(merged)) {
    const current = serverById.get(item.id);
    if (current && JSON.stringify(current) === JSON.stringify(item)) continue;

    pushes.push({ item, lastKnownRevisionDate: current ? current.revisionDate : null });
  }

  return pushes;
}

/** Whether merging the server state into local produced anything new to push. */
export function hasLocalChanges(server: VaultState, merged: VaultState): boolean {
  return planPush(server, merged).length > 0;
}
