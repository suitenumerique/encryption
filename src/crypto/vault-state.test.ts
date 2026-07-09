import {
  type TofuEntry,
  type VaultState,
  addEncryptionKey,
  deleteTofu,
  emptyVaultState,
  mergeVaultState,
  setTofu,
} from '@encryption/src/crypto/vault-state';

// Deterministic PRNG for the property-based tests below: driving the random
// state generation from an explicit seed makes any failing case reproducible
// (plain Math.random() would not be, and it is unavailable here anyway).
function rng(seed: number): () => number {
  let s = seed >>> 0;

  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

const normalize = (s: VaultState): VaultState => mergeVaultState(s, emptyVaultState());

function randomState(rand: () => number): VaultState {
  let state = emptyVaultState();

  const keyCount = Math.floor(rand() * 4);
  for (let v = 1; v <= keyCount; v++) {
    state = addEncryptionKey(state, { version: v, algo: 'x-wing', publicKey: `pk${v}`, secretKey: `sk${v}`, createdAt: v * 1000 });
  }

  const userCount = Math.floor(rand() * 4);
  for (let u = 0; u < userCount; u++) {
    const userId = `u${Math.floor(rand() * 3)}`;
    const status = rand() < 0.5 ? 'trusted' : 'refused';
    const at = Math.floor(rand() * 5) * 100;
    state = setTofu(state, userId, `fp${Math.floor(rand() * 3)}`, status, at);
    if (rand() < 0.2) state = deleteTofu(state, userId, at + 50);
  }

  return state;
}

describe('mergeVaultState algebraic laws', () => {
  it('is commutative, associative, and idempotent over random states', () => {
    for (let seed = 1; seed <= 300; seed++) {
      const rand = rng(seed);
      const a = randomState(rand);
      const b = randomState(rand);
      const c = randomState(rand);

      expect(mergeVaultState(a, b)).toEqual(mergeVaultState(b, a));
      expect(mergeVaultState(mergeVaultState(a, b), c)).toEqual(mergeVaultState(a, mergeVaultState(b, c)));
      expect(mergeVaultState(a, a)).toEqual(normalize(a));
    }
  });
});

describe('encryption keys are a grow-only union', () => {
  it('keeps every version minted on either device', () => {
    let a = emptyVaultState();
    a = addEncryptionKey(a, { version: 1, algo: 'x-wing', publicKey: 'p1', secretKey: 's1', createdAt: 1 });
    let b = mergeVaultState(a, emptyVaultState());

    a = addEncryptionKey(a, { version: 2, algo: 'x-wing', publicKey: 'p2', secretKey: 's2', createdAt: 2 });
    b = addEncryptionKey(b, { version: 3, algo: 'x-wing', publicKey: 'p3', secretKey: 's3', createdAt: 3 });

    const merged = mergeVaultState(a, b);

    expect(merged.encryptionKeys.map((k) => k.version)).toEqual([1, 2, 3]);
    expect(merged.active.encKeyVersion).toBe(3);
  });
});

describe('TOFU conflict resolution', () => {
  const entry = (t: Partial<TofuEntry>): VaultState => ({
    ...emptyVaultState(),
    tofu: { bob: { fingerprint: 'fp', status: 'trusted', deleted: false, revisionDate: 0, ...t } },
  });

  it('newer decision wins', () => {
    const older = entry({ status: 'trusted', revisionDate: 100 });
    const newer = entry({ status: 'refused', revisionDate: 200 });

    expect(mergeVaultState(older, newer).tofu.bob.status).toBe('refused');
    expect(mergeVaultState(newer, older).tofu.bob.status).toBe('refused');
  });

  it('refused wins a same-revision tie (fail-safe)', () => {
    const trusted = entry({ status: 'trusted', revisionDate: 100 });
    const refused = entry({ status: 'refused', revisionDate: 100 });

    expect(mergeVaultState(trusted, refused).tofu.bob.status).toBe('refused');
    expect(mergeVaultState(refused, trusted).tofu.bob.status).toBe('refused');
  });

  it('a newer delete is not resurrected by an older add', () => {
    const a = setTofu(emptyVaultState(), 'bob', 'fp', 'trusted', 100);
    const deleted = deleteTofu(a, 'bob', 200);
    const staleReadd = setTofu(a, 'bob', 'fp', 'trusted', 150);

    const merged = mergeVaultState(deleted, staleReadd);
    expect(merged.tofu.bob.deleted).toBe(true);
    expect(merged.tofu.bob.revisionDate).toBe(200);
  });

  it('a delete does lose to a genuinely newer re-add', () => {
    const base = setTofu(emptyVaultState(), 'bob', 'fp', 'trusted', 100);
    const deleted = deleteTofu(base, 'bob', 150);
    const readd = setTofu(base, 'bob', 'fp', 'trusted', 200);

    expect(mergeVaultState(deleted, readd).tofu.bob.deleted).toBe(false);
  });
});
