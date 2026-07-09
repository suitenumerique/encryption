/**
 * Mapping between the in-memory VaultState and the per-item records the server
 * stores. Each logical record (one identity generation, one encryption key
 * version, one TOFU entry, and the active pointer) becomes one opaque ciphertext
 * row on the server. Splitting per item is what lets the server enforce
 * optimistic concurrency on a single `revisionDate` without ever reading the
 * content, and lets a mutation push only what changed.
 */
import { z } from 'zod';

import {
  type VaultState,
  activePointerSchema,
  emptyVaultState,
  encryptionKeyEntrySchema,
  identityEntrySchema,
  mergeVaultState,
  tofuEntrySchema,
} from '@encryption/src/crypto/vault-state';
import { VaultItemTypeSchema } from '@encryption/src/shared/schemas/vault';

// Single source of truth lives in the shared wire schema; re-exported here under
// the name the crypto layer (and the manifest) already use.
export const itemTypeSchema = VaultItemTypeSchema;
export type ItemType = z.infer<typeof itemTypeSchema>;

const itemBase = { id: z.string(), revisionDate: z.number() };

/**
 * The plaintext of one item, before it is sealed with the VRK. Discriminated on
 * `type`, so a consumer that narrows on `type` gets the exact `payload` shape and
 * no branch can pair the wrong payload with a type. The TOFU payload inlines its
 * `userId` because that key is part of the item, not the stored entry.
 */
export const plainItemSchema = z.discriminatedUnion('type', [
  z.object({ ...itemBase, type: z.literal('identity'), payload: identityEntrySchema }),
  z.object({ ...itemBase, type: z.literal('encryptionKey'), payload: encryptionKeyEntrySchema }),
  z.object({ ...itemBase, type: z.literal('tofu'), payload: tofuEntrySchema.extend({ userId: z.string() }) }),
  z.object({ ...itemBase, type: z.literal('active'), payload: activePointerSchema }),
]);
export type PlainItem = z.infer<typeof plainItemSchema>;

const ACTIVE_ID = 'active';

export function stateToItems(state: VaultState): PlainItem[] {
  const items: PlainItem[] = [];

  for (const e of state.identities) {
    items.push({ id: `identity:${e.generation}`, type: 'identity', revisionDate: e.createdAt, payload: e });
  }

  for (const e of state.encryptionKeys) {
    items.push({ id: `enc:${e.version}`, type: 'encryptionKey', revisionDate: e.createdAt, payload: e });
  }

  for (const [userId, t] of Object.entries(state.tofu)) {
    items.push({ id: `tofu:${userId}`, type: 'tofu', revisionDate: t.revisionDate, payload: { userId, ...t } });
  }

  // The `active` pointer names WHICH generation + key version is current. The
  // vault keeps the full history (identities across continuity generations,
  // encryption keys across rotations) as grow-only lists, so "current" cannot be
  // inferred from the list alone (you can reactivate an OLDER one). It is a signed
  // vault item on purpose, NOT read from the server's `disabledAt`: the directory
  // is server-controlled and unsigned, whereas this pointer is covered by the
  // identity-signed manifest, so "which of MY OWN keys is current" is the user's
  // tamper-evident decision, not the server's. (The directory's `disabledAt` is
  // the right source for OTHERS discovering your active key; the two are separate
  // trust domains.) `identityGen` only spans more than one value once continuity
  // is wired; until then it is just the single current generation.
  const activeIdentity = state.identities.find((e) => e.generation === state.active.identityGen);
  const activeKey = state.encryptionKeys.find((e) => e.version === state.active.encKeyVersion);
  const activeRevision = Math.max(activeIdentity?.createdAt ?? 0, activeKey?.createdAt ?? 0);
  items.push({ id: ACTIVE_ID, type: 'active', revisionDate: activeRevision, payload: state.active });

  return items.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

export function itemsToState(items: PlainItem[]): VaultState {
  const state = emptyVaultState();

  for (const item of items) {
    if (item.type === 'identity') state.identities.push(item.payload);
    else if (item.type === 'encryptionKey') state.encryptionKeys.push(item.payload);
    else if (item.type === 'tofu') {
      const { userId, ...entry } = item.payload;
      state.tofu[userId] = entry;
    } else if (item.type === 'active') {
      state.active = item.payload;
    }
  }

  // Normalize (sort the grow-only lists, recompute active bounds) by merging
  // with an empty state, so the result is independent of item order.
  return mergeVaultState(state, emptyVaultState());
}
