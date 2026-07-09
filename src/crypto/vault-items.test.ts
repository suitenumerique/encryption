import { itemsToState, stateToItems } from '@encryption/src/crypto/vault-items';
import { addEncryptionKey, addIdentity, emptyVaultState, mergeVaultState, setTofu } from '@encryption/src/crypto/vault-state';

function sampleState() {
  let s = emptyVaultState();
  s = addIdentity(s, { generation: 1, algo: 'ed25519', signaturePublicKey: 'sp1', signatureSecretKey: 'ss1', createdAt: 10 });
  s = addEncryptionKey(s, { version: 1, algo: 'x-wing', publicKey: 'p1', secretKey: 's1', createdAt: 10 });
  s = addEncryptionKey(s, { version: 2, algo: 'x-wing', publicKey: 'p2', secretKey: 's2', createdAt: 20 });
  s = setTofu(s, 'bob', 'fp-bob', 'trusted', 30);
  s = setTofu(s, 'carol', 'fp-carol', 'refused', 40);

  return s;
}

describe('vault item mapping', () => {
  it('round-trips state -> items -> state', () => {
    const state = sampleState();

    expect(itemsToState(stateToItems(state))).toEqual(mergeVaultState(state, emptyVaultState()));
  });

  it('emits one item per record plus the active pointer, sorted by id', () => {
    const items = stateToItems(sampleState());
    const ids = items.map((i) => i.id);

    expect(ids).toEqual([...ids].sort());
    expect(ids).toContain('active');
    expect(ids).toContain('enc:2');
    expect(ids).toContain('tofu:bob');
    expect(items).toHaveLength(6); // 1 identity + 2 keys + 2 tofu + active
  });

  it('is insensitive to item order on the way back', () => {
    const items = stateToItems(sampleState());
    const shuffled = [...items].reverse();

    expect(itemsToState(shuffled)).toEqual(itemsToState(items));
  });
});
