import fc from 'fast-check';
import sodium from 'libsodium-wrappers-sumo';
import { beforeAll, describe, expect, it } from 'vitest';

import { ensureSodium } from '@encryption/src/crypto/encryption';
import {
  type RandomSource,
  type ShamirShare,
  checkHelperCommitments,
  combineShares,
  commit,
  decodeCommitments,
  decodeShare,
  encodeCommitments,
  encodeShare,
  evaluateCommitments,
  isCanonicalScalar,
  lagrangeAtZero,
  pedersenH,
  randomScalar,
  reshareContribution,
  splitSecret,
  sumCommitments,
  sumSubShares,
  verifyShare,
} from '@encryption/src/crypto/shamir';

beforeAll(async () => {
  await ensureSodium();
});

function seededRandom(seed: number): RandomSource {
  let state = seed >>> 0;

  return (length) => {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      bytes[i] = state >>> 24;
    }

    return bytes;
  };
}

function* combinations<T>(items: T[], size: number, start = 0, chosen: T[] = []): Generator<T[]> {
  if (chosen.length === size) {
    yield [...chosen];

    return;
  }

  for (let i = start; i <= items.length - (size - chosen.length); i++) {
    chosen.push(items[i]);
    yield* combinations(items, size, i + 1, chosen);
    chosen.pop();
  }
}

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

// A scalar from 64 arbitrary bytes, like randomScalar does.
const secretArb = fc.uint8Array({ minLength: 64, maxLength: 64 }).map((wide) => sodium.crypto_core_ristretto255_scalar_reduce(wide));

// A council: n slots (distinct, 1..255), a threshold k with 1 <= k <= n.
const councilArb = fc
  .integer({ min: 1, max: 8 })
  .chain((n) => fc.tuple(fc.uniqueArray(fc.integer({ min: 1, max: 255 }), { minLength: n, maxLength: n }), fc.integer({ min: 1, max: n })));

describe('splitSecret / combineShares', () => {
  it('gives the secret back from every subset of k shares', () => {
    fc.assert(
      fc.property(secretArb, councilArb, (secret, [xs, k]) => {
        const { shares } = splitSecret(secret, xs, k);

        for (const subset of combinations(shares, k)) {
          expect(combineShares(subset)).toEqual(secret);
        }
      }),
      { numRuns: 25 }
    );
  });

  it('gives the secret back from more than k shares too', () => {
    fc.assert(
      fc.property(secretArb, councilArb, (secret, [xs, k]) => {
        expect(combineShares(splitSecret(secret, xs, k).shares)).toEqual(secret);
      }),
      { numRuns: 25 }
    );
  });

  it('does not give the secret back from k - 1 shares', () => {
    fc.assert(
      fc.property(
        secretArb,
        councilArb.filter(([, k]) => k >= 2),
        (secret, [xs, k]) => {
          const { shares } = splitSecret(secret, xs, k);

          expect(combineShares(shares.slice(0, k - 1))).not.toEqual(secret);
        }
      ),
      { numRuns: 25 }
    );
  });

  it('keeps the secret as every share for k = 1', () => {
    const secret = randomScalar();
    for (const share of splitSecret(secret, [3, 9], 1).shares) expect(share.value).toEqual(secret);
  });

  it('refuses malformed parameters', () => {
    const secret = randomScalar();
    expect(() => splitSecret(secret, [], 1)).toThrow();
    expect(() => splitSecret(secret, [0, 1], 1)).toThrow();
    expect(() => splitSecret(secret, [1, 256], 1)).toThrow();
    expect(() => splitSecret(secret, [1, 1], 1)).toThrow();
    expect(() => splitSecret(secret, [1, 2], 0)).toThrow();
    expect(() => splitSecret(secret, [1, 2], 3)).toThrow();
    // Above the group order: not a scalar, it would not come back the same.
    expect(() => splitSecret(new Uint8Array(32).fill(0xff), [1, 2], 2)).toThrow();

    const { shares } = splitSecret(secret, [1, 2], 2);
    expect(() => combineShares([shares[0], shares[0]])).toThrow();
  });
});

describe('Pedersen commitments', () => {
  it('verify every share of the split, and only at its own slot', () => {
    fc.assert(
      fc.property(secretArb, councilArb, (secret, [xs, k]) => {
        const { shares, commitments } = splitSecret(secret, xs, k);

        expect(commitments).toHaveLength(k);
        for (const share of shares) {
          expect(verifyShare(share, commitments)).toBe(true);
          const elsewhere = (share.x % 255) + 1;
          if (k > 1 && !xs.includes(elsewhere)) expect(verifyShare({ ...share, x: elsewhere }, commitments)).toBe(false);
        }
      }),
      { numRuns: 25 }
    );
  });

  it('refuse a share whose value or blinding was changed', () => {
    const { shares, commitments } = splitSecret(randomScalar(), [1, 2, 3], 2);
    const one = sodium.crypto_core_ristretto255_scalar_reduce(Uint8Array.from({ length: 64 }, (_, i) => (i === 0 ? 1 : 0)));
    const bump = (scalar: Uint8Array) => sodium.crypto_core_ristretto255_scalar_add(scalar, one);

    expect(verifyShare({ ...shares[0], value: bump(shares[0].value) }, commitments)).toBe(false);
    expect(verifyShare({ ...shares[0], blinding: bump(shares[0].blinding) }, commitments)).toBe(false);
    // A real share of another split of the same secret.
    expect(verifyShare(splitSecret(randomScalar(), [1, 2, 3], 2).shares[0], commitments)).toBe(false);
    expect(verifyShare({ ...shares[0], value: new Uint8Array(32).fill(0xff) }, commitments)).toBe(false);
  });

  // Feldman's constant term would be s·G, which a discrete logarithm (a quantum
  // computer) turns back into s. Pedersen's is blinded: two splits of the same
  // secret commit to it differently, and neither is s·G.
  it('hide the secret behind the blinding', () => {
    const secret = randomScalar();
    const a = splitSecret(secret, [1, 2], 2).commitments[0];
    const b = splitSecret(secret, [1, 2], 2).commitments[0];

    expect(hex(a)).not.toBe(hex(b));
    expect(hex(a)).not.toBe(hex(sodium.crypto_scalarmult_ristretto255_base(secret)));
  });

  it('use a second generator distinct from the base point', () => {
    const base = sodium.crypto_scalarmult_ristretto255_base(
      sodium.crypto_core_ristretto255_scalar_reduce(Uint8Array.from({ length: 64 }, (_, i) => (i === 0 ? 1 : 0)))
    );

    expect(sodium.crypto_core_ristretto255_is_valid_point(pedersenH())).toBe(true);
    expect(hex(pedersenH())).not.toBe(hex(base));
  });

  it('commit to a·G + b·H, evaluated like the polynomial', () => {
    const { shares, commitments } = splitSecret(randomScalar(), [5, 6, 7], 3);
    for (const share of shares) expect(hex(evaluateCommitments(commitments, share.x))).toBe(hex(commit(share.value, share.blinding)));
  });

  // Frozen bytes: a change to the generator, the coefficient order or the
  // encodings would make shares and commitments already handed out stop verifying.
  it('match a frozen vector', () => {
    const random = seededRandom(42);
    const secret = randomScalar(random);
    const { shares, commitments } = splitSecret(secret, [1, 2, 3], 2, random);

    expect(hex(pedersenH())).toMatchInlineSnapshot(`"f26f52739850031568e1f56441bb0ec8dcbb3a8e156845158fb7d8d11e1b4772"`);
    expect(hex(encodeShare(shares[1]))).toMatchInlineSnapshot(
      `"02d93ef3a44961c391fd96f6cfdb741ba5f696fdded6a703dcedd73f2544b8660fe7e32ce5105291ad7ee479d25f4844c90a137d72a1484637b89ec183acd9a403"`
    );
    expect(hex(encodeCommitments(commitments))).toMatchInlineSnapshot(
      `"1e3abae5b7d7ee0c8dd43de5b4b943aa4625523f62fd5dabe5b9bde00540560a7087762503a23b5d16943bb1107094bcde8d2498f642df37f1ad19a096601a6f"`
    );
  });
});

describe('Lagrange weights', () => {
  it('add up to 1 (the constant polynomial 1 interpolates to 1)', () => {
    fc.assert(
      fc.property(fc.uniqueArray(fc.integer({ min: 1, max: 255 }), { minLength: 1, maxLength: 12 }), (xs) => {
        const sum = xs.reduce<Uint8Array>((acc, _, i) => sodium.crypto_core_ristretto255_scalar_add(acc, lagrangeAtZero(xs, i)), new Uint8Array(32));
        const one = new Uint8Array(32);
        one[0] = 1;

        expect(hex(sum)).toBe(hex(one));
      })
    );
  });
});

describe('resharing', () => {
  function reshare(split: { shares: ShamirShare[]; commitments: Uint8Array[] }, helperXs: number[], targetXs: number[], targetK: number) {
    const helpers = split.shares.filter((share) => helperXs.includes(share.x));
    const contributions = helpers.map((share) => reshareContribution(share, helperXs, targetXs, targetK));

    return {
      contributions,
      shares: targetXs.map((x, j) =>
        sumSubShares(
          x,
          contributions.map((c) => c.subShares[j])
        )
      ),
      commitments: sumCommitments(contributions.map((c) => c.commitments)),
    };
  }

  it('moves the same secret to new slots and a new threshold, under commitments with the same constant term', () => {
    fc.assert(
      fc.property(
        secretArb,
        councilArb,
        fc
          .uniqueArray(fc.integer({ min: 1, max: 255 }), { minLength: 1, maxLength: 8 })
          .chain((targetXs) => fc.tuple(fc.constant(targetXs), fc.integer({ min: 1, max: targetXs.length }))),
        (secret, [xs, k], [targetXs, targetK]) => {
          const split = splitSecret(secret, xs, k);
          const helperXs = xs.slice(0, k);
          const reshared = reshare(split, helperXs, targetXs, targetK);

          expect(hex(reshared.commitments[0])).toBe(hex(split.commitments[0]));
          for (const share of reshared.shares) expect(verifyShare(share, reshared.commitments)).toBe(true);
          for (const subset of combinations(reshared.shares, targetK)) {
            expect(combineShares(subset)).toEqual(secret);
          }
        }
      ),
      { numRuns: 15 }
    );
  });

  it('works with any k helpers, not only the first ones', () => {
    const secret = randomScalar();
    const xs = [1, 2, 3, 4, 5, 6];
    const split = splitSecret(secret, xs, 3);

    for (const helperXs of combinations(xs, 3)) {
      const reshared = reshare(split, helperXs, [2, 3, 7, 8, 9], 2);
      expect(combineShares([reshared.shares[0], reshared.shares[4]])).toEqual(secret);
    }
  });

  it('lets anyone check that each helper started from its own share', () => {
    const split = splitSecret(randomScalar(), [1, 2, 3, 4], 2);
    const helperXs = [1, 3];
    const honest = reshareContribution(split.shares[0], helperXs, [1, 2, 5], 2);
    expect(checkHelperCommitments(split.commitments, 1, helperXs, honest.commitments)).toBe(true);

    // A helper resharing a share that is not its own (or a wrong one) is caught
    // before anything moves.
    const forged = reshareContribution({ ...split.shares[2], x: 1 }, helperXs, [1, 2, 5], 2);
    expect(checkHelperCommitments(split.commitments, 1, helperXs, forged.commitments)).toBe(false);
    expect(checkHelperCommitments(split.commitments, 2, helperXs, honest.commitments)).toBe(false);
    expect(checkHelperCommitments(split.commitments, 3, helperXs, honest.commitments)).toBe(false);
  });

  // A sub-share the helper changed after committing does not verify, so the new
  // custodian refuses it instead of adding a wrong value into its share.
  it('lets each new custodian check its sub-shares', () => {
    const split = splitSecret(randomScalar(), [1, 2, 3], 2);
    const { subShares, commitments } = reshareContribution(split.shares[0], [1, 2], [4, 5], 2);

    expect(subShares.every((s) => verifyShare(s, commitments))).toBe(true);
    expect(verifyShare({ ...subShares[0], value: subShares[1].value }, commitments)).toBe(false);
  });

  // A departed custodian's old share lives on the old polynomial: mixed with new
  // shares it gives garbage, which is what makes a resharing a revocation.
  it('makes old shares useless with new ones', () => {
    const secret = randomScalar();
    const split = splitSecret(secret, [1, 2, 3, 4], 2);
    const reshared = reshare(split, [1, 2], [1, 2, 3, 5], 2);

    expect(combineShares([split.shares[3], reshared.shares[3]])).not.toEqual(secret);
    expect(verifyShare(split.shares[3], reshared.commitments)).toBe(false);
    expect(combineShares([reshared.shares[0], reshared.shares[3]])).toEqual(secret);
  });

  it('refuses a helper outside the helper set, and sub-shares of another slot', () => {
    const { shares } = splitSecret(randomScalar(), [4], 1);
    expect(() => reshareContribution(shares[0], [1, 2], [1, 2], 1)).toThrow();
    expect(() => sumSubShares(1, [{ ...shares[0], x: 2 }])).toThrow();
    expect(() => sumCommitments([])).toThrow();
  });
});

describe('encodings', () => {
  it('round-trip a share', () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 255 }), secretArb, secretArb, (x, value, blinding) => {
        expect(decodeShare(encodeShare({ x, value, blinding }))).toEqual({ x, value, blinding });
      })
    );
  });

  it('refuse slot 0, a wrong length and a non-canonical scalar', () => {
    const share = encodeShare({ x: 1, value: randomScalar(), blinding: randomScalar() });

    expect(() => decodeShare(Uint8Array.of(0, ...share.slice(1)))).toThrow();
    expect(() => decodeShare(share.slice(0, 64))).toThrow();
    expect(() => decodeShare(Uint8Array.of(1, ...new Uint8Array(32).fill(0xff), ...share.slice(33)))).toThrow();
    expect(isCanonicalScalar(new Uint8Array(32).fill(0xff))).toBe(false);
  });

  it('round-trip commitments and refuse what is not a list of points', () => {
    const { commitments } = splitSecret(randomScalar(), [1, 2, 3], 3);

    expect(decodeCommitments(encodeCommitments(commitments))).toEqual(commitments);
    expect(() => decodeCommitments(new Uint8Array(0))).toThrow();
    expect(() => decodeCommitments(new Uint8Array(33))).toThrow();
    expect(() => decodeCommitments(new Uint8Array(32).fill(0xff))).toThrow();
  });
});
