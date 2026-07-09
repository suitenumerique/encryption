import 'fake-indexeddb/auto';
import sodium from 'libsodium-wrappers-sumo';

import { base64ToUint8, exportPublicKeyAsBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import { signIdentityContinuity, verifyIdentityContinuity } from '@encryption/src/crypto/key-registration';
import { type SignatureKeyPair, generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import { closeVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { handleAcceptFingerprint, handleCheckFingerprints, handleRefuseFingerprint } from '@encryption/src/vault/operations/fingerprint-registry';
import { handleGenerateKeys } from '@encryption/src/vault/operations/generate-keys';
import { type ContinuityLink, resolveContinuity } from '@encryption/src/vault/operations/identity-continuity';

// Accept/refuse fingerprint are write-through (they push via the sync engine).
// Unit tests have no server, so stand in a `handleSync` that just applies the
// write-through mutation locally (as a successful push would) and reports ok.
jest.mock('@encryption/src/vault/operations/vault-sync-run', () => {
  const actual = jest.requireActual('@encryption/src/vault/vault-keys');

  return {
    handleSync: async (userId: string, payload?: { mutate?: (s: unknown) => unknown }) => {
      if (payload?.mutate) await actual.mutateVault(userId, payload.mutate);

      return { status: 'ok', revision: 0 };
    },
  };
});

beforeAll(async () => {
  await sodium.ready;
});

afterAll(() => {
  closeVaultBroadcastChannel();
});

// One directory link: `identity` endorsed by `previous`.
async function mkLink(remoteUserId: string, previous: SignatureKeyPair, identity: SignatureKeyPair, generation: number): Promise<ContinuityLink> {
  const signaturePublicKey = exportPublicKeyAsBase64(identity.publicKey);
  const sig = await signIdentityContinuity(
    { userId: remoteUserId, generation, algo: 'ed25519', signaturePublicKeyWire: base64ToUint8(signaturePublicKey) },
    previous.secretKey
  );

  return {
    signaturePublicKey,
    previousSignaturePublicKey: exportPublicKeyAsBase64(previous.publicKey),
    generation,
    algo: 'ed25519',
    continuitySignature: uint8ToBase64(sig),
  };
}

const fp = (kp: SignatureKeyPair) => computeKeyFingerprint(exportPublicKeyAsBase64(kp.publicKey));

// A `deps` stub standing in for the directory fetch: serves a fixed chain for
// one contact and an empty chain for anyone else.
function chainFetcher(remoteUserId: string, chain: ContinuityLink[]) {
  return { fetchContinuityChain: async (id: string) => (id === remoteUserId ? chain : []) };
}

describe('identity continuity crypto', () => {
  it('round-trips sign then verify, and rejects a wrong signer', async () => {
    const prev = await generateSignatureKeyPair();
    const next = await generateSignatureKeyPair();
    const record = { userId: 'bob', generation: 2, algo: 'ed25519', signaturePublicKeyWire: base64ToUint8(exportPublicKeyAsBase64(next.publicKey)) };

    const sig = await signIdentityContinuity(record, prev.secretKey);
    expect(await verifyIdentityContinuity(record, exportPublicKeyAsBase64(prev.publicKey), uint8ToBase64(sig))).toBe(true);

    const other = await generateSignatureKeyPair();
    expect(await verifyIdentityContinuity(record, exportPublicKeyAsBase64(other.publicKey), uint8ToBase64(sig))).toBe(false);
  });
});

describe('resolveContinuity (multi-hop walk)', () => {
  it('follows a two-hop chain v0 -> v1 -> v2 back to the pinned v0', async () => {
    const v0 = await generateSignatureKeyPair(); // pinned
    const v1 = await generateSignatureKeyPair();
    const v2 = await generateSignatureKeyPair(); // current
    const chain = [await mkLink('bob', v1, v2, 3), await mkLink('bob', v0, v1, 2)];

    const outcome = await resolveContinuity('bob', await fp(v0), chain);
    expect(outcome.chained).toBe(true);
    expect(outcome.newFingerprint).toBe(await fp(v2));
  });

  it('refuses a chain longer than the hop cap', async () => {
    const a = await generateSignatureKeyPair();
    const b = await generateSignatureKeyPair();
    const link = await mkLink('bob', a, b, 2);
    const tooLong: ContinuityLink[] = Array.from({ length: 6 }, () => link);

    expect((await resolveContinuity('bob', 'whatever', tooLong)).chained).toBe(false);
  });

  it('refuses a non-contiguous chain', async () => {
    const v0 = await generateSignatureKeyPair();
    const v1 = await generateSignatureKeyPair();
    const v2 = await generateSignatureKeyPair();
    const unrelated = await generateSignatureKeyPair();
    // chain[0].previous is v1, but chain[1] is `unrelated`, not v1.
    const chain = [await mkLink('bob', v1, v2, 3), await mkLink('bob', v0, unrelated, 2)];

    expect((await resolveContinuity('bob', await fp(v0), chain)).chained).toBe(false);
  });

  it('refuses when the chain never reaches the pinned identity', async () => {
    const pinned = await generateSignatureKeyPair();
    const a = await generateSignatureKeyPair();
    const b = await generateSignatureKeyPair();
    const chain = [await mkLink('bob', a, b, 2)]; // a -> b, but `a` is not the pinned key

    expect((await resolveContinuity('bob', await fp(pinned), chain)).chained).toBe(false);
  });
});

describe('continuity inside checkFingerprints', () => {
  it('records a first encounter as unknown (allowed, not trusted) and flags a later CHANGE as mismatch', async () => {
    const userId = 'u-first-sight';
    await handleGenerateKeys(userId);
    const v1 = await generateSignatureKeyPair();
    const v2 = await generateSignatureKeyPair();

    // First sight on an actual share (record: true): recorded as unknown (seen, not
    // verified), never auto-trusted.
    const first = await handleCheckFingerprints(userId, { userFingerprints: { bob: await fp(v1) } }, { ...chainFetcher('bob', []), record: true });
    expect(first.results[0]).toMatchObject({ userId: 'bob', status: 'unknown' });

    // A DIFFERENT fingerprint now surfaces as a mismatch, because v1 was recorded.
    const changed = await handleCheckFingerprints(userId, { userFingerprints: { bob: await fp(v2) } }, chainFetcher('bob', []));
    expect(changed.results[0].status).toBe('mismatch');
  });

  it('a read-only check (record absent) records nothing, so it never floods the vault', async () => {
    const userId = 'u-readonly';
    await handleGenerateKeys(userId);
    const v1 = await generateSignatureKeyPair();
    const v2 = await generateSignatureKeyPair();

    // Two read-only checks of a first-seen contact: both 'unknown', nothing pinned.
    expect((await handleCheckFingerprints(userId, { userFingerprints: { bob: await fp(v1) } }, chainFetcher('bob', []))).results[0].status).toBe(
      'unknown'
    );

    // Because nothing was recorded, a later DIFFERENT fingerprint is still just a
    // first sight ('unknown'), not a mismatch. Only an actual share records.
    const changed = await handleCheckFingerprints(userId, { userFingerprints: { bob: await fp(v2) } }, chainFetcher('bob', []));
    expect(changed.results[0].status).toBe('unknown');
  });

  it('carries a trusted status forward across a valid one-hop link', async () => {
    const userId = 'u-cont';
    await handleGenerateKeys(userId);

    const v1 = await generateSignatureKeyPair();
    const v2 = await generateSignatureKeyPair();
    await handleAcceptFingerprint(userId, { userId: 'bob', fingerprint: await fp(v1) });

    const chain = [await mkLink('bob', v1, v2, 2)];
    const v2Fp = await fp(v2);

    const { results } = await handleCheckFingerprints(userId, { userFingerprints: { bob: v2Fp } }, chainFetcher('bob', chain));
    expect(results[0]).toMatchObject({ userId: 'bob', providedFingerprint: v2Fp, status: 'trusted' });
  });

  it('propagates a refused status (a refused contact cannot launder a rotation into trust)', async () => {
    const userId = 'u-cont-refused';
    await handleGenerateKeys(userId);

    const v1 = await generateSignatureKeyPair();
    const v2 = await generateSignatureKeyPair();
    await handleRefuseFingerprint(userId, { userId: 'mallory', fingerprint: await fp(v1) });

    const { results } = await handleCheckFingerprints(
      userId,
      { userFingerprints: { mallory: await fp(v2) } },
      chainFetcher('mallory', [await mkLink('mallory', v1, v2, 2)])
    );
    expect(results[0].status).toBe('refused');
  });

  it('flags a mismatch when the directory has no continuity chain', async () => {
    const userId = 'u-cont-none';
    await handleGenerateKeys(userId);

    const v1 = await generateSignatureKeyPair();
    const v2 = await generateSignatureKeyPair();
    await handleAcceptFingerprint(userId, { userId: 'bob', fingerprint: await fp(v1) });

    const { results } = await handleCheckFingerprints(userId, { userFingerprints: { bob: await fp(v2) } }, chainFetcher('bob', []));
    expect(results[0].status).toBe('mismatch');
  });

  it('flags a mismatch when the chain does not reach the pinned identity', async () => {
    const userId = 'u-cont-wrong';
    await handleGenerateKeys(userId);

    const realV1 = await generateSignatureKeyPair();
    const attackerV1 = await generateSignatureKeyPair();
    const attackerV2 = await generateSignatureKeyPair();
    await handleAcceptFingerprint(userId, { userId: 'bob', fingerprint: await fp(realV1) });

    const { results } = await handleCheckFingerprints(
      userId,
      { userFingerprints: { bob: await fp(attackerV2) } },
      chainFetcher('bob', [await mkLink('bob', attackerV1, attackerV2, 2)])
    );
    expect(results[0].status).toBe('mismatch');
  });
});
