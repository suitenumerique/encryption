import sodium from 'libsodium-wrappers-sumo';
import { beforeAll, describe, expect, it } from 'vitest';

import { generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import type { SealedItem } from '@encryption/src/crypto/vault-manifest';
import { addEncryptionKey, addIdentity, councilPin, emptyVaultState, mergeVaultState, pinCouncil, setTofu } from '@encryption/src/crypto/vault-state';
import { type PulledVault, type PutItemInput, type PutOutcome, type SyncCrypto, sync, syncOnce } from '@encryption/src/vault/operations/vault-sync';

// A minimal in-memory stand-in for the server: opaque items + the last manifest,
// with the same per-item optimistic-concurrency rule as the real route.
class FakeServer {
  items = new Map<string, SealedItem>();
  manifest = '';
  manifestSig = '';
  revision = 0;

  async fetch(): Promise<PulledVault | null> {
    if (this.revision === 0) return null;

    return { sealed: [...this.items.values()], manifest: this.manifest, manifestSig: this.manifestSig, revision: this.revision };
  }

  async putItem(input: PutItemInput): Promise<PutOutcome> {
    const current = this.items.get(input.item.id);
    if (current && (input.lastKnownRevisionDate === null || current.revisionDate > input.lastKnownRevisionDate)) {
      return { ok: false, conflict: true };
    }

    this.items.set(input.item.id, input.item);
    this.manifest = input.manifest;
    this.manifestSig = input.manifestSig;
    this.revision = input.revision;

    return { ok: true, revision: input.revision };
  }
}

function deviceState() {
  let s = emptyVaultState();
  s = addIdentity(s, { generation: 1, algo: 'ed25519', signaturePublicKey: 'sp', signatureSecretKey: 'ss', createdAt: 10 });
  s = addEncryptionKey(s, { version: 1, algo: 'x-wing', publicKey: 'p1', secretKey: 's1', createdAt: 10 });
  s = setTofu(s, 'bob', 'fp-bob', 'trusted', 20);

  return mergeVaultState(s, emptyVaultState());
}

let vrk: Uint8Array;
let crypto_: SyncCrypto;

beforeAll(async () => {
  await sodium.ready;
  vrk = sodium.randombytes_buf(32);
  const identity = await generateSignatureKeyPair();
  crypto_ = { vrk, identitySecretKey: identity.secretKey, trustedIdentityPublicKey: identity.publicKey, identityGen: 1 };
});

describe('sync engine', () => {
  it('pushes local state to an empty server, and a second device converges to it', async () => {
    const server = new FakeServer();

    const a = await sync(deviceState(), 0, server, crypto_);
    expect(a.status).toBe('ok');

    const b = await sync(emptyVaultState(), 0, server, crypto_);
    expect(b.status).toBe('ok');
    if (a.status === 'ok' && b.status === 'ok') {
      expect(b.state).toEqual(a.state);
      expect(b.state.tofu.bob.status).toBe('trusted');
    }
  });

  // The council pins travel sealed like the rest: a verification made on one device reaches the others.
  it('carries a council pin and its verification to every device', async () => {
    const server = new FakeServer();
    const laptop = await sync(pinCouncil(deviceState(), 'dinum', 'h1', false, 30), 0, server, crypto_);
    if (laptop.status !== 'ok') throw new Error(laptop.status);

    const phone = await sync(emptyVaultState(), 0, server, crypto_);
    if (phone.status !== 'ok') throw new Error(phone.status);
    expect(councilPin(phone.state, 'dinum')).toEqual({ genesisHash: 'h1', pinnedAt: 30, verifiedAt: null });

    const verified = await sync(pinCouncil(phone.state, 'dinum', 'h1', true, 40), phone.revision, server, crypto_);
    expect(verified.status).toBe('ok');

    const back = await sync(laptop.state, laptop.revision, server, crypto_);
    if (back.status !== 'ok') throw new Error(back.status);
    expect(councilPin(back.state, 'dinum')).toEqual({ genesisHash: 'h1', pinnedAt: 30, verifiedAt: 40 });
  });

  // Two devices joined before syncing, each shown another council under one id: both end with the first in force.
  it('converges two devices that pinned different councils on the earliest', async () => {
    const server = new FakeServer();
    await sync(deviceState(), 0, server, crypto_);
    const base = await sync(emptyVaultState(), 0, server, crypto_);
    if (base.status !== 'ok') throw new Error(base.status);

    const laptop = await sync(pinCouncil(base.state, 'dinum', 'real', false, 30), base.revision, server, crypto_);
    const phone = await sync(pinCouncil(base.state, 'dinum', 'forged', true, 50), base.revision, server, crypto_);
    if (laptop.status !== 'ok' || phone.status !== 'ok') throw new Error('sync failed');

    const after = await sync(laptop.state, laptop.revision, server, crypto_);
    if (after.status !== 'ok') throw new Error(after.status);
    for (const state of [after.state, phone.state]) expect(councilPin(state, 'dinum')).toMatchObject({ genesisHash: 'real', verifiedAt: null });
    expect(Object.keys(phone.state.councils.dinum).sort()).toEqual(['forged', 'real']);
  });

  it('is a no-op on a second sync with no local change', async () => {
    const server = new FakeServer();
    const state = deviceState();
    await sync(state, 0, server, crypto_);

    const puts: PutItemInput[] = [];
    const spy = { fetch: () => server.fetch(), putItem: (i: PutItemInput) => (puts.push(i), server.putItem(i)) };

    const again = await syncOnce(state, server.revision, spy, crypto_);
    expect(again.status).toBe('ok');
    expect(puts).toHaveLength(0);
  });

  it('refuses a tampered pull without merging', async () => {
    const server = new FakeServer();
    await sync(deviceState(), 0, server, crypto_);
    // A valid-looking but wrong signature, and separately a garbage one: both refuse.
    server.manifestSig = sodium.to_base64(sodium.randombytes_buf(64), sodium.base64_variants.ORIGINAL);
    expect((await syncOnce(emptyVaultState(), 0, server, crypto_)).status).toBe('integrity-error');

    server.manifestSig = '!!!not base64!!!';
    expect((await syncOnce(emptyVaultState(), 0, server, crypto_)).status).toBe('integrity-error');
  });

  it('refuses when the server acks a revision other than the one committed (equivocation)', async () => {
    const server = new FakeServer();
    await sync(deviceState(), 0, server, crypto_);

    // The server accepts the write but lies about the revision, returning a lower
    // number so it could later solicit a second, different manifest at the same
    // revision. The engine must treat the mismatched ack as an integrity error.
    const lying = {
      fetch: () => server.fetch(),
      putItem: async (i: PutItemInput): Promise<PutOutcome> => {
        const outcome = await server.putItem(i);

        return outcome.ok ? { ok: true, revision: i.revision - 1 } : outcome;
      },
    };

    const local = setTofu(emptyVaultState(), 'carol', 'fp-carol', 'refused', 99);
    expect((await syncOnce(local, server.revision, lying, crypto_)).status).toBe('integrity-error');
  });

  it('retries after a 409 and eventually succeeds', async () => {
    const server = new FakeServer();
    await sync(deviceState(), 0, server, crypto_);

    let failNext = true;
    const flaky = {
      fetch: () => server.fetch(),
      putItem: (i: PutItemInput): Promise<PutOutcome> => {
        if (failNext) {
          failNext = false;
          return Promise.resolve({ ok: false, conflict: true });
        }
        return server.putItem(i);
      },
    };

    // A second device makes a fresh local change, hits one 409, then succeeds.
    const local = setTofu(emptyVaultState(), 'carol', 'fp-carol', 'refused', 99);
    const result = await sync(local, 0, flaky, crypto_);

    expect(result.status).toBe('ok');
    if (result.status === 'ok') expect(result.state.tofu.carol.status).toBe('refused');
  });
});
