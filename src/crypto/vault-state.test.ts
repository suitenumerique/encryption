import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { vaultStateArb } from '@encryption/src/crypto/testing/arbitraries';
import {
  type TofuEntry,
  type VaultState,
  addEncryptionKey,
  deleteTofu,
  emptyVaultState,
  keyMaterialChanged,
  mergeVaultState,
  setTofu,
} from '@encryption/src/crypto/vault-state';

const normalize = (s: VaultState): VaultState => mergeVaultState(s, emptyVaultState());

describe('mergeVaultState algebraic laws', () => {
  it('is commutative, associative, and idempotent over random states', () => {
    fc.assert(
      fc.property(vaultStateArb, vaultStateArb, vaultStateArb, (a, b, c) => {
        expect(mergeVaultState(a, b)).toEqual(mergeVaultState(b, a));
        expect(mergeVaultState(mergeVaultState(a, b), c)).toEqual(mergeVaultState(a, mergeVaultState(b, c)));
        expect(mergeVaultState(a, a)).toEqual(normalize(a));
      }),
      { numRuns: 300 }
    );
  });

  it('never loses a key version or a TOFU entry either side knew', () => {
    fc.assert(
      fc.property(vaultStateArb, vaultStateArb, (a, b) => {
        const merged = mergeVaultState(a, b);

        for (const side of [a, b]) {
          for (const k of side.encryptionKeys) expect(merged.encryptionKeys.some((m) => m.version === k.version)).toBe(true);
          for (const userId of Object.keys(side.tofu)) expect(merged.tofu[userId]).toBeDefined();
        }
      })
    );
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

describe('keyMaterialChanged', () => {
  const key = (version: number) => ({ version, algo: 'x-wing', publicKey: `pub-${version}`, secretKey: `sec-${version}`, createdAt: 1_000 });

  it('reports no change between identical states', () => {
    const state = addEncryptionKey(setTofu(emptyVaultState(), 'bob', 'fp', 'trusted', 100), key(1));

    expect(keyMaterialChanged(state, state)).toBe(false);
  });

  // The case that made every trust decision look like a key rotation.
  it('ignores a TOFU-only change', () => {
    const before = addEncryptionKey(emptyVaultState(), key(1));

    expect(keyMaterialChanged(before, setTofu(before, 'bob', 'fp', 'trusted', 100))).toBe(false);
  });

  it('ignores a status change on an already-known contact', () => {
    const before = setTofu(emptyVaultState(), 'bob', 'fp', 'unknown', 100);

    expect(keyMaterialChanged(before, setTofu(before, 'bob', 'fp', 'trusted', 200))).toBe(false);
  });

  it('flags a new encryption key version', () => {
    const before = addEncryptionKey(emptyVaultState(), key(1));

    expect(keyMaterialChanged(before, addEncryptionKey(before, key(2)))).toBe(true);
  });
});
