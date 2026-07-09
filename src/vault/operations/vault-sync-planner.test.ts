import { addEncryptionKey, emptyVaultState, mergeVaultState, setTofu } from '@encryption/src/crypto/vault-state';
import { hasLocalChanges, planPush } from '@encryption/src/vault/operations/vault-sync-planner';

function base() {
  let s = emptyVaultState();
  s = addEncryptionKey(s, { version: 1, algo: 'x-wing', publicKey: 'p1', secretKey: 's1', createdAt: 10 });
  s = setTofu(s, 'bob', 'fp-bob', 'trusted', 20);

  return mergeVaultState(s, emptyVaultState());
}

describe('planPush', () => {
  it('pushes nothing when local equals server', () => {
    const server = base();

    expect(planPush(server, server)).toEqual([]);
    expect(hasLocalChanges(server, server)).toBe(false);
  });

  it('pushes a brand-new TOFU entry with a null last-known revision', () => {
    const server = base();
    const merged = setTofu(server, 'carol', 'fp-carol', 'trusted', 30);

    const pushes = planPush(server, merged);

    expect(pushes).toHaveLength(1);
    expect(pushes[0].item.id).toBe('tofu:carol');
    expect(pushes[0].lastKnownRevisionDate).toBeNull();
  });

  it('carries the server revisionDate when updating an existing entry', () => {
    const server = base();
    const merged = setTofu(server, 'bob', 'fp-bob', 'refused', 40);

    const pushes = planPush(server, merged);

    expect(pushes.map((p) => p.item.id)).toEqual(['tofu:bob']);
    expect(pushes[0].lastKnownRevisionDate).toBe(20); // bob's revisionDate on the server
  });

  it('pushes both the new key and the moved active pointer on a rotation', () => {
    const server = base();
    const merged = addEncryptionKey(server, { version: 2, algo: 'x-wing', publicKey: 'p2', secretKey: 's2', createdAt: 50 });

    const ids = planPush(server, merged)
      .map((p) => p.item.id)
      .sort();

    expect(ids).toEqual(['active', 'enc:2']);
  });
});
