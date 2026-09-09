import fc from 'fast-check';

import { type VaultState, addEncryptionKey, addIdentity, deleteTofu, emptyVaultState, setTofu } from '@encryption/src/crypto/vault-state';

const epochMs = fc.integer({ min: 0, max: 2_000_000_000_000 });

// Small id spaces on purpose: collisions between the two sides of a merge are
// where the conflict-resolution rules actually get exercised.
const keyedEntries = fc.array(fc.tuple(fc.integer({ min: 1, max: 4 }), epochMs), { maxLength: 4 });

const tofuOp = fc.record({
  userId: fc.constantFrom('u0', 'u1', 'u2'),
  fingerprint: fc.constantFrom('fp0', 'fp1', 'fp2'),
  status: fc.constantFrom('unknown', 'trusted', 'refused'),
  at: fc.integer({ min: 0, max: 1_000 }),
  thenDelete: fc.boolean(),
});

// A vault state built only through the public mutators, so every generated
// value respects the invariants real code relies on (active pointer <= max key).
export const vaultStateArb: fc.Arbitrary<VaultState> = fc
  .tuple(keyedEntries, keyedEntries, fc.array(tofuOp, { maxLength: 6 }))
  .map(([identities, keys, tofuOps]) => {
    let state = emptyVaultState();

    for (const [generation, createdAt] of identities) {
      state = addIdentity(state, {
        generation,
        algo: 'ed25519',
        signaturePublicKey: `sp${generation}`,
        signatureSecretKey: `ss${generation}`,
        createdAt,
      });
    }

    for (const [version, createdAt] of keys) {
      state = addEncryptionKey(state, { version, algo: 'x-wing', publicKey: `pk${version}`, secretKey: `sk${version}`, createdAt });
    }

    for (const op of tofuOps) {
      state = setTofu(state, op.userId, op.fingerprint, op.status, op.at);
      if (op.thenDelete) state = deleteTofu(state, op.userId, op.at + 50);
    }

    return state;
  });
