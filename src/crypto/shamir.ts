/**
 * Verifiable Shamir secret sharing (Pedersen) over the ristretto255 group, for
 * the recovery council (architecture.md F.1).
 *
 * The secret is a scalar `s`. The dealer draws two random polynomials of degree
 * `k - 1`, `f` with `f(0) = s` and a blinding `g`, gives each custodian the pair
 * `(f(x), g(x))` at their slot number `x`, and publishes one commitment per
 * coefficient, `C_j = a_j·G + b_j·H`. Anyone can check a share against them:
 * `f(x)·G + g(x)·H = Σ C_j·x^j`. Any `k` shares give `s` back (Lagrange at 0),
 * `k - 1` leave it undetermined.
 *
 * Pedersen and not Feldman: Feldman's commitments contain `s·G`, which a
 * quantum computer would turn back into `s` from a copy of the database. Here
 * the blinding makes the commitments reveal nothing about `s` against any
 * attacker; only the binding (a share cannot be swapped for another that still
 * verifies) rests on the discrete logarithm.
 *
 * Every scalar and point operation is libsodium's (constant time); this file
 * only arranges them. `H` comes from hashing a domain label to the group, so
 * nobody knows its logarithm in base `G`.
 *
 * Resharing (Desmedt-Jajodia) moves the same secret to a new set of slots and a
 * new threshold without rebuilding it anywhere: each of `k` helpers splits its
 * Lagrange-weighted share with commitments of its own, whose constant term
 * anyone checks against the current commitments, and each new custodian adds
 * up the sub-shares it receives. The new commitments are the sums of the
 * helpers', and their constant term stays the one the user signed.
 *
 * libsodium must be ready (`ensureSodium`) before any call.
 */
import sodium from 'libsodium-wrappers-sumo';

import { DOMAIN_COUNCIL_PEDERSEN_GENERATOR } from '@encryption/src/shared/crypto-domains';

export const SHAMIR_SCALAR_BYTES = 32;
export const SHAMIR_POINT_BYTES = 32;
export const SHAMIR_SHARE_BYTES = 1 + 2 * SHAMIR_SCALAR_BYTES;
export const SHAMIR_MAX_SLOT = 255;

export interface ShamirShare {
  /** The slot number, 1..255, never 0 (the polynomial at 0 is the secret). */
  x: number;
  /** f(x) */
  value: Uint8Array;
  /** g(x) */
  blinding: Uint8Array;
}

/** One point per coefficient, constant term first. */
export type Commitments = Uint8Array[];

export type RandomSource = (length: number) => Uint8Array;

const defaultRandom: RandomSource = (length) => crypto.getRandomValues(new Uint8Array(length));

const IDENTITY = new Uint8Array(SHAMIR_POINT_BYTES);

let generatorH: Uint8Array | null = null;

/** The second generator, from a hash: nobody knows log_G(H). */
export function pedersenH(): Uint8Array {
  generatorH ??= sodium.crypto_core_ristretto255_from_hash(sodium.crypto_hash_sha512(new TextEncoder().encode(DOMAIN_COUNCIL_PEDERSEN_GENERATOR)));

  return generatorH;
}

/** A uniformly random scalar: 64 random bytes reduced modulo the group order. */
export function randomScalar(random: RandomSource = defaultRandom): Uint8Array {
  const wide = random(64);
  const scalar = sodium.crypto_core_ristretto255_scalar_reduce(wide);
  wide.fill(0);

  return scalar;
}

function scalarOf(n: number): Uint8Array {
  const bytes = new Uint8Array(SHAMIR_SCALAR_BYTES);
  bytes[0] = n & 0xff;
  bytes[1] = (n >> 8) & 0xff;

  return bytes;
}

const ZERO_SCALAR = new Uint8Array(SHAMIR_SCALAR_BYTES);

/** True for the 32-byte little-endian encoding of a scalar below the group order. */
export function isCanonicalScalar(bytes: Uint8Array): boolean {
  if (bytes.length !== SHAMIR_SCALAR_BYTES) return false;

  const wide = new Uint8Array(64);
  wide.set(bytes);

  return equalBytes(sodium.crypto_core_ristretto255_scalar_reduce(wide), bytes);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];

  return diff === 0;
}

// libsodium refuses a product equal to the identity (a zero scalar), which a
// random polynomial reaches with probability 2^-252.
function mulBase(scalar: Uint8Array): Uint8Array {
  try {
    return sodium.crypto_scalarmult_ristretto255_base(scalar);
  } catch {
    return IDENTITY.slice();
  }
}

function mulPoint(scalar: Uint8Array, point: Uint8Array): Uint8Array {
  try {
    return sodium.crypto_scalarmult_ristretto255(scalar, point);
  } catch {
    return IDENTITY.slice();
  }
}

/** `a·G + b·H`. */
export function commit(a: Uint8Array, b: Uint8Array): Uint8Array {
  return sodium.crypto_core_ristretto255_add(mulBase(a), mulPoint(b, pedersenH()));
}

function assertSlots(xs: number[]): void {
  if (xs.length === 0 || xs.length > SHAMIR_MAX_SLOT) throw new Error('Shamir: between 1 and 255 slots');
  if (new Set(xs).size !== xs.length) throw new Error('Shamir: slots must be distinct');
  for (const x of xs) {
    if (!Number.isInteger(x) || x < 1 || x > SHAMIR_MAX_SLOT) throw new Error('Shamir: a slot is an integer between 1 and 255');
  }
}

function assertThreshold(k: number, n: number): void {
  if (!Number.isInteger(k) || k < 1 || k > n) throw new Error('Shamir: the threshold is between 1 and the number of slots');
}

/** Horner over scalars: coefficients constant term first. */
function evaluate(coefficients: Uint8Array[], x: number): Uint8Array {
  const xs = scalarOf(x);
  let value: Uint8Array = coefficients[coefficients.length - 1].slice();

  for (let degree = coefficients.length - 2; degree >= 0; degree--) {
    const next = sodium.crypto_core_ristretto255_scalar_add(sodium.crypto_core_ristretto255_scalar_mul(value, xs), coefficients[degree]);
    value.fill(0);
    value = next;
  }

  return value;
}

/** `Σ C_j·x^j`, what a share at slot `x` must commit to. */
export function evaluateCommitments(commitments: Commitments, x: number): Uint8Array {
  if (commitments.length === 0) throw new Error('Shamir: no commitment');

  const xs = scalarOf(x);
  let point: Uint8Array = commitments[commitments.length - 1];

  for (let degree = commitments.length - 2; degree >= 0; degree--) {
    point = sodium.crypto_core_ristretto255_add(mulPoint(xs, point), commitments[degree]);
  }

  return point;
}

/**
 * Split `secret` (with blinding constant `blinding0`, random when omitted) into
 * one share per slot of `xs`, any `k` of which give it back, and the
 * commitments every share verifies against.
 */
export function splitSecret(
  secret: Uint8Array,
  xs: number[],
  k: number,
  random: RandomSource = defaultRandom,
  blinding0?: Uint8Array
): { shares: ShamirShare[]; commitments: Commitments } {
  assertSlots(xs);
  assertThreshold(k, xs.length);
  if (!isCanonicalScalar(secret)) throw new Error('Shamir: the secret is not a canonical scalar');

  const f: Uint8Array[] = [secret.slice()];
  const g: Uint8Array[] = [blinding0 ? blinding0.slice() : randomScalar(random)];
  for (let degree = 1; degree < k; degree++) {
    f.push(randomScalar(random));
    g.push(randomScalar(random));
  }

  const commitments = f.map((a, j) => commit(a, g[j]));
  const shares = xs.map((x) => ({ x, value: evaluate(f, x), blinding: evaluate(g, x) }));

  for (const coefficient of [...f, ...g]) coefficient.fill(0);

  return { shares, commitments };
}

/** Whether a share lies on the committed polynomials. */
export function verifyShare(share: ShamirShare, commitments: Commitments): boolean {
  try {
    if (!isCanonicalScalar(share.value) || !isCanonicalScalar(share.blinding)) return false;

    return equalBytes(commit(share.value, share.blinding), evaluateCommitments(commitments, share.x));
  } catch {
    return false;
  }
}

/** The Lagrange weight of slot `xs[index]` for an interpolation at 0 over exactly the slots `xs`. */
export function lagrangeAtZero(xs: number[], index: number): Uint8Array {
  let numerator: Uint8Array = scalarOf(1);
  let denominator: Uint8Array = scalarOf(1);

  xs.forEach((x, j) => {
    if (j === index) return;
    numerator = sodium.crypto_core_ristretto255_scalar_mul(numerator, scalarOf(x));
    denominator = sodium.crypto_core_ristretto255_scalar_mul(
      denominator,
      sodium.crypto_core_ristretto255_scalar_sub(scalarOf(x), scalarOf(xs[index]))
    );
  });

  return sodium.crypto_core_ristretto255_scalar_mul(numerator, sodium.crypto_core_ristretto255_scalar_invert(denominator));
}

/**
 * The secret from shares of one split. Every share is used, so pass exactly the
 * shares wanted, each verified first: a single wrong one gives a wrong secret.
 */
export function combineShares(shares: ShamirShare[]): Uint8Array {
  const xs = shares.map((share) => share.x);
  assertSlots(xs);

  let secret: Uint8Array = ZERO_SCALAR.slice();
  shares.forEach((share, index) => {
    const weighted = sodium.crypto_core_ristretto255_scalar_mul(share.value, lagrangeAtZero(xs, index));
    const next = sodium.crypto_core_ristretto255_scalar_add(secret, weighted);
    weighted.fill(0);
    secret.fill(0);
    secret = next;
  });

  return secret;
}

/**
 * Resharing, helper side: what one of the `k` helpers sends to each target slot,
 * and the commitments those sub-shares verify against. `helperXs` is the exact
 * set of helper slots (every helper must use the same set, it fixes the Lagrange
 * weights), `share` this helper's own share.
 */
export function reshareContribution(
  share: ShamirShare,
  helperXs: number[],
  targetXs: number[],
  targetThreshold: number,
  random: RandomSource = defaultRandom
): { subShares: ShamirShare[]; commitments: Commitments } {
  assertSlots(helperXs);

  const index = helperXs.indexOf(share.x);
  if (index === -1) throw new Error('Shamir: the helper is not in the helper set');

  const lambda = lagrangeAtZero(helperXs, index);
  const value = sodium.crypto_core_ristretto255_scalar_mul(share.value, lambda);
  const blinding = sodium.crypto_core_ristretto255_scalar_mul(share.blinding, lambda);
  const { shares, commitments } = splitSecret(value, targetXs, targetThreshold, random, blinding);
  value.fill(0);
  blinding.fill(0);

  return { subShares: shares, commitments };
}

/**
 * Whether a helper's resharing commitments start from its own share of the
 * current split: their constant term must be `λ_i·Σ C_j·x_i^j`. Public data
 * only, so the server checks it on arrival as well as every vault.
 */
export function checkHelperCommitments(current: Commitments, helperX: number, helperXs: number[], helperCommitments: Commitments): boolean {
  try {
    const index = helperXs.indexOf(helperX);
    if (index === -1 || helperCommitments.length === 0) return false;

    const expected = mulPoint(lagrangeAtZero(helperXs, index), evaluateCommitments(current, helperX));

    return equalBytes(expected, helperCommitments[0]);
  } catch {
    return false;
  }
}

/** The commitments of a reshared split: the helpers' summed coefficient by coefficient. */
export function sumCommitments(perHelper: Commitments[]): Commitments {
  if (perHelper.length === 0) throw new Error('Shamir: no commitments to add up');

  const length = perHelper[0].length;
  if (perHelper.some((c) => c.length !== length)) throw new Error('Shamir: commitments of different degrees');

  return perHelper[0].map((_, j) =>
    perHelper.slice(1).reduce<Uint8Array>((sum, c) => sodium.crypto_core_ristretto255_add(sum, c[j]), perHelper[0][j])
  );
}

/** Resharing, recipient side: the new share is the sum of one sub-share per helper. */
export function sumSubShares(x: number, subShares: ShamirShare[]): ShamirShare {
  if (subShares.length === 0) throw new Error('Shamir: no sub-share to add up');
  if (subShares.some((s) => s.x !== x)) throw new Error('Shamir: a sub-share of another slot');

  const add = (pick: (s: ShamirShare) => Uint8Array): Uint8Array =>
    subShares.slice(1).reduce<Uint8Array>((sum, s) => sodium.crypto_core_ristretto255_scalar_add(sum, pick(s)), pick(subShares[0]).slice());

  return { x, value: add((s) => s.value), blinding: add((s) => s.blinding) };
}

export function equalPoints(a: Uint8Array, b: Uint8Array): boolean {
  return equalBytes(a, b);
}

/** `[x:1][value:32][blinding:32]`, the form a share is wrapped in. */
export function encodeShare(share: ShamirShare): Uint8Array {
  const bytes = new Uint8Array(SHAMIR_SHARE_BYTES);
  bytes[0] = share.x;
  bytes.set(share.value, 1);
  bytes.set(share.blinding, 1 + SHAMIR_SCALAR_BYTES);

  return bytes;
}

export function decodeShare(bytes: Uint8Array): ShamirShare {
  if (bytes.length !== SHAMIR_SHARE_BYTES || bytes[0] === 0) throw new Error('Shamir: malformed share');

  const share = { x: bytes[0], value: bytes.slice(1, 1 + SHAMIR_SCALAR_BYTES), blinding: bytes.slice(1 + SHAMIR_SCALAR_BYTES) };
  if (!isCanonicalScalar(share.value) || !isCanonicalScalar(share.blinding)) throw new Error('Shamir: malformed share');

  return share;
}

export function wipeShare(share: ShamirShare): void {
  share.value.fill(0);
  share.blinding.fill(0);
}

/** Concatenated points, the form commitments are signed and stored in. */
export function encodeCommitments(commitments: Commitments): Uint8Array {
  const bytes = new Uint8Array(commitments.length * SHAMIR_POINT_BYTES);
  commitments.forEach((point, j) => bytes.set(point, j * SHAMIR_POINT_BYTES));

  return bytes;
}

export function decodeCommitments(bytes: Uint8Array): Commitments {
  if (bytes.length === 0 || bytes.length % SHAMIR_POINT_BYTES !== 0) throw new Error('Shamir: malformed commitments');

  const points: Commitments = [];
  for (let offset = 0; offset < bytes.length; offset += SHAMIR_POINT_BYTES) {
    const point = bytes.slice(offset, offset + SHAMIR_POINT_BYTES);
    if (!sodium.crypto_core_ristretto255_is_valid_point(point)) throw new Error('Shamir: malformed commitments');
    points.push(point);
  }

  return points;
}
