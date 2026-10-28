import 'fake-indexeddb/auto';
import { type Mock, beforeEach, describe, expect, it, vi } from 'vitest';

import { type RosterRecord, requestFingerprint, rosterHash, signRoster } from '@encryption/src/crypto/council';
import { escrowRecordFromWire } from '@encryption/src/crypto/council-protocol';
import { generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { base64ToUint8, exportPublicKeyAsBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { mnemonicToKey } from '@encryption/src/crypto/mnemonic';
import { type SignatureKeyPair, generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import { signAuthPublicKeyBinding } from '@encryption/src/crypto/vault-unlock';
import type { CouncilEscrowBody, RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import { VaultErrorCode } from '@encryption/src/shared/vault-error';
import { handleFetchPublicKeys } from '@encryption/src/vault/operations/fetch-public-keys';
import { handleCheckFingerprints } from '@encryption/src/vault/operations/fingerprint-registry';
import { deriveKeyring, loadWithIdentity } from '@encryption/src/vault/operations/onboarding';
import {
  handleCheckCouncilEscrow,
  handleCouncilContribute,
  handleCouncilReshareBatch,
  handleCreateCouncilEscrow,
  handleSignCouncilRoster,
  handleStartCouncilRequest,
  handleVerifyCouncilRoster,
} from '@encryption/src/vault/operations/recovery-council';

vi.mock('@encryption/src/vault/operations/fetch-public-keys');
vi.mock('@encryption/src/vault/operations/fingerprint-registry');
vi.mock('@encryption/src/vault/operations/vault-restore');
// The real deriveKeyring runs Argon2id (64 MiB); the fake keeps its contract: the
// keyring is derived from the phrase it is given.
vi.mock('@encryption/src/vault/operations/onboarding', () => ({ loadWithIdentity: vi.fn(), deriveKeyring: vi.fn() }));

const COUNCIL = 'dinum';
const ME = '11111111-0000-4000-8000-000000000000';

interface Person {
  id: string;
  identity: SignatureKeyPair;
  kem: Awaited<ReturnType<typeof generateUserKeyPair>>;
}

const wireB64 = (identity: SignatureKeyPair) => exportPublicKeyAsBase64(identity.publicKey);
const buffer = (bytes: Uint8Array) => bytes.slice().buffer as ArrayBuffer;

async function person(n: number): Promise<Person> {
  return { id: `${n}`.repeat(8) + '-0000-4000-8000-000000000000', identity: await generateSignatureKeyPair(), kem: await generateUserKeyPair() };
}

function directory(people: Person[], overrides: Record<string, Record<string, unknown>> = {}) {
  return {
    users: Object.fromEntries(
      people.map((p) => [
        p.id,
        {
          userId: p.id,
          signaturePublicKey: buffer(base64ToUint8(wireB64(p.identity))),
          identityFingerprint: '',
          version: 1,
          createdAtMillis: 1,
          verified: true,
          encryptionPublicKey: buffer(base64ToUint8(exportPublicKeyAsBase64(p.kem.publicKey))),
          ...overrides[p.id],
        },
      ])
    ),
  };
}

function versionWire(record: RosterRecord, signatures: Array<{ identity: SignatureKeyPair; signature: Uint8Array }>): RosterVersionWire {
  return {
    version: record.version,
    threshold: record.threshold,
    previous_roster_hash: uint8ToBase64(record.previousRosterHash),
    members: record.members.map((m) => ({
      slot: m.slot,
      user_id: m.userId,
      identity_public_key: uint8ToBase64(m.identityPublicKeyWire),
      name: null,
    })),
    signatures: signatures.map((s) => ({ identity_public_key: wireB64(s.identity), signature: uint8ToBase64(s.signature) })),
  };
}

async function genesis(members: Person[], threshold: number): Promise<{ record: RosterRecord; wire: RosterVersionWire }> {
  const record: RosterRecord = {
    councilId: COUNCIL,
    version: 1,
    threshold,
    previousRosterHash: new Uint8Array(0),
    members: members.map((p, i) => ({ slot: i + 1, userId: p.id, identityPublicKeyWire: base64ToUint8(wireB64(p.identity)) })),
  };
  const signatures = await Promise.all(
    members.map(async (p) => ({ identity: p.identity, signature: await signRoster(record, p.identity.secretKey) }))
  );

  return { record, wire: versionWire(record, signatures) };
}

let me: Person;
let a: Person;
let b: Person;
let c: Person;

function loadAs(p: Person) {
  (loadWithIdentity as Mock).mockResolvedValue({
    loaded: {
      vrk: new Uint8Array(32).fill(1),
      state: {
        identities: [
          {
            generation: 1,
            algo: 'ed25519',
            signaturePublicKey: wireB64(p.identity),
            signatureSecretKey: uint8ToBase64(p.identity.secretKey),
            createdAt: 1,
          },
        ],
        encryptionKeys: [{ version: 1, algo: 'x-wing', publicKey: '', secretKey: uint8ToBase64(p.kem.secretKey), createdAt: 1 }],
        active: { identityGen: 1, encKeyVersion: 1 },
        tofu: {},
      },
    },
    identitySecret: p.identity.secretKey,
  });
}

beforeEach(async () => {
  vi.clearAllMocks();
  me = { ...(await person(1)), id: ME };
  [a, b, c] = await Promise.all([person(2), person(3), person(4)]);
  loadAs(me);

  (deriveKeyring as Mock).mockImplementation(async (_userId: string, _vrk: Uint8Array, identitySecret: Uint8Array, lang: string, phrase: string) => {
    const auth = await generateSignatureKeyPair();

    return {
      recoveryPhrase: phrase,
      keyring: {
        wrapped_vrk: uint8ToBase64(new Uint8Array(48)),
        auth_public_key: uint8ToBase64(auth.publicKey),
        auth_pub_sig: uint8ToBase64(await signAuthPublicKeyBinding(auth.publicKey, identitySecret)),
        kdf_ops: 3,
        kdf_mem: 64 * 1024 * 1024,
        lang,
      },
    };
  });
  (handleFetchPublicKeys as Mock).mockResolvedValue(directory([me, a, b, c]));
});

describe('enrollment', () => {
  it('shows the head fingerprint of a verified chain, and refuses an unsigned one', async () => {
    const { wire } = await genesis([a, b, c], 2);

    expect(await handleVerifyCouncilRoster(ME, { councilId: COUNCIL, chain: [wire] })).toMatchObject({ version: 1 });
    await expect(
      handleVerifyCouncilRoster(ME, { councilId: COUNCIL, chain: [{ ...wire, signatures: wire.signatures.slice(1) }] })
    ).rejects.toMatchObject({
      code: VaultErrorCode.VAULT_INTEGRITY_FAILED,
    });
  });

  it('splits a fresh phrase over the custodians, its credential derived from that phrase', async () => {
    const { wire } = await genesis([a, b, c], 2);

    const body = await handleCreateCouncilEscrow(ME, { councilId: COUNCIL, chain: [wire], lang: 'french' });

    expect(body.shares.map((s) => s.slot)).toEqual([1, 2, 3]);
    expect(body.threshold).toBe(2);
    const phrase = (deriveKeyring as Mock).mock.calls[0][4] as string;
    expect(mnemonicToKey(phrase, 'french')).toHaveLength(32);
  });

  // The server cannot slip its own key in front of a custodian's identity.
  it('refuses a custodian whose directory key is not bound to the identity the roster pins', async () => {
    const { wire } = await genesis([a, b, c], 2);
    const impostor = await generateSignatureKeyPair();
    (handleFetchPublicKeys as Mock).mockResolvedValue(
      directory([me, a, b, c], { [b.id]: { signaturePublicKey: buffer(base64ToUint8(wireB64(impostor))) } })
    );

    await expect(handleCreateCouncilEscrow(ME, { councilId: COUNCIL, chain: [wire] })).rejects.toMatchObject({
      code: VaultErrorCode.UNTRUSTED_RECIPIENT,
    });
  });

  it('audits an escrow: signed by me, head reachable from the version it pins', async () => {
    const { wire } = await genesis([a, b, c], 2);
    const body = await handleCreateCouncilEscrow(ME, { councilId: COUNCIL, chain: [wire] });
    const record = await recordOf(body, wire);

    expect((await handleCheckCouncilEscrow(ME, { record, chain: [wire] })).status).toBe('ok');
    expect((await handleCheckCouncilEscrow(ME, { record: { ...record, threshold: 1 }, chain: [wire] })).status).toBe('tampered');
    expect((await handleCheckCouncilEscrow(ME, { record, chain: [{ ...wire, threshold: 3 }] })).status).toBe('chain-broken');
  });
});

async function recordOf(body: CouncilEscrowBody, head: RosterVersionWire) {
  const { capsuleHash, rosterHash: hash } = await import('@encryption/src/crypto/council');
  const { rosterRecordFromWire } = await import('@encryption/src/crypto/council-protocol');
  const { default: sodium } = await import('libsodium-wrappers-sumo');

  return {
    council_id: COUNCIL,
    roster_version: head.version,
    roster_hash: uint8ToBase64(await hash(rosterRecordFromWire(COUNCIL, head))),
    threshold: body.threshold,
    escrow_created_at_millis: body.escrow_created_at_millis,
    credential_auth_public_key_hash: uint8ToBase64(sodium.crypto_hash_sha256(base64ToUint8(body.credential.auth_public_key))),
    secret_commitment: body.secret_commitment,
    share_commitments: body.share_commitments,
    shares: await Promise.all(
      body.shares.map(async (s) => ({ slot: s.slot, capsule_hash: uint8ToBase64(await capsuleHash(base64ToUint8(s.wrapped_share))) }))
    ),
    escrow_signature: body.escrow_signature,
  };
}

describe('contribution', () => {
  async function requestFor(custodian: Person) {
    const { wire } = await genesis([a, b, c], 2);
    const body = await handleCreateCouncilEscrow(ME, { councilId: COUNCIL, chain: [wire] });
    const record = await recordOf(body, wire);
    const ephemeral = await generateUserKeyPair();
    const slot = [a, b, c].indexOf(custodian) + 1;

    loadAs(custodian);

    return {
      detail: {
        id: 'b9f1c6a2-0000-4000-8000-000000000000',
        council_id: COUNCIL,
        user_id: ME,
        ephemeral_public_key: exportPublicKeyAsBase64(ephemeral.publicKey),
        escrow: record,
        capsule: { kind: 'direct' as const, generation: 1, slot, wrapped_share: body.shares[slot - 1].wrapped_share },
      },
      code: await requestFingerprint(base64ToUint8(exportPublicKeyAsBase64(ephemeral.publicKey))),
    };
  }

  it('hands the share over remotely, or in person to the key whose code was read', async () => {
    const { detail, code } = await requestFor(a);

    expect((await handleCouncilContribute(a.id, { detail, inPerson: false })).in_person).toBe(false);
    expect((await handleCouncilContribute(a.id, { detail, inPerson: true, meetingCode: code.replace(/(\d{5})/g, '$1 ') })).in_person).toBe(true);
  });

  it('refuses the in-person share when the code on the screen is another one', async () => {
    const { detail, code } = await requestFor(a);
    const wrong = code.slice(0, -1) + (code.endsWith('0') ? '1' : '0');

    await expect(handleCouncilContribute(a.id, { detail, inPerson: true, meetingCode: wrong })).rejects.toMatchObject({
      code: VaultErrorCode.INVALID_KEY_BINDING,
    });
  });

  // Another escrow's share at the same slot, wrapped for the same custodian:
  // only the Pedersen check against the signed commitments tells them apart.
  it('refuses a share that does not lie on the commitments the user signed', async () => {
    const { detail } = await requestFor(a);
    loadAs(me);
    const { wire } = await genesis([a, b, c], 2);
    const other = await handleCreateCouncilEscrow(ME, { councilId: COUNCIL, chain: [wire] });
    loadAs(a);

    await expect(
      handleCouncilContribute(a.id, {
        detail: { ...detail, capsule: { kind: 'direct', generation: 1, slot: 1, wrapped_share: other.shares[0].wrapped_share } },
        inPerson: false,
      })
    ).rejects.toMatchObject({ code: VaultErrorCode.VAULT_INTEGRITY_FAILED });
  });

  it('refuses an escrow the person asking did not sign', async () => {
    const { detail } = await requestFor(b);

    await expect(
      handleCouncilContribute(b.id, { detail: { ...detail, escrow: { ...detail.escrow, threshold: 1 } }, inPerson: false })
    ).rejects.toMatchObject({
      code: VaultErrorCode.VAULT_INTEGRITY_FAILED,
    });
    // The signed record itself is genuine.
    expect(escrowRecordFromWire(ME, detail.escrow).threshold).toBe(2);
  });
});

describe('signing a roster', () => {
  it('signs a first version that names me with my own key', async () => {
    loadAs(a);
    const { record } = await genesis([a, b, c], 2);

    expect((await handleSignCouncilRoster(a.id, { councilId: COUNCIL, chain: [], proposal: versionWire(record, []) })).signature).toBeTruthy();
  });

  it('refuses a version that names me with another key', async () => {
    loadAs(a);
    const { record } = await genesis([a, b, c], 2);
    const forged = {
      ...record,
      members: record.members.map((m) => (m.userId === a.id ? { ...m, identityPublicKeyWire: base64ToUint8(wireB64(c.identity)) } : m)),
    };

    await expect(handleSignCouncilRoster(a.id, { councilId: COUNCIL, chain: [], proposal: versionWire(forged, []) })).rejects.toMatchObject({
      code: VaultErrorCode.VAULT_INTEGRITY_FAILED,
    });
  });

  it('wants every newcomer checked out of band before signing, and the proposal to follow the chain', async () => {
    loadAs(a);
    const { record, wire } = await genesis([a, b, c], 2);
    const d = await person(5);
    const next: RosterRecord = {
      councilId: COUNCIL,
      version: 2,
      threshold: 2,
      previousRosterHash: await rosterHash(record),
      members: [...record.members.slice(0, 2), { slot: 4, userId: d.id, identityPublicKeyWire: base64ToUint8(wireB64(d.identity)) }],
    };

    (handleCheckFingerprints as Mock).mockResolvedValue({ results: [{ userId: d.id, status: 'unknown' }] });
    await expect(handleSignCouncilRoster(a.id, { councilId: COUNCIL, chain: [wire], proposal: versionWire(next, []) })).rejects.toMatchObject({
      code: VaultErrorCode.UNTRUSTED_RECIPIENT,
    });

    (handleCheckFingerprints as Mock).mockResolvedValue({ results: [{ userId: d.id, status: 'trusted' }] });
    expect((await handleSignCouncilRoster(a.id, { councilId: COUNCIL, chain: [wire], proposal: versionWire(next, []) })).signature).toBeTruthy();

    await expect(
      handleSignCouncilRoster(a.id, {
        councilId: COUNCIL,
        chain: [wire],
        proposal: versionWire({ ...next, previousRosterHash: new Uint8Array(32) }, []),
      })
    ).rejects.toMatchObject({ code: VaultErrorCode.VAULT_INTEGRITY_FAILED });
  });
});

describe('locked-out browser', () => {
  it('keeps the request key in this browser and shows its meeting code', async () => {
    const started = await handleStartCouncilRequest(ME);

    expect(started.fingerprint).toBe(await requestFingerprint(base64ToUint8(started.ephemeralPublicKey)));
  });
});

describe('resharing', () => {
  it('sends transfer keys once per session, and refuses a target that is not the verified head', async () => {
    loadAs(a);
    const { wire } = await genesis([a, b, c], 2);
    const batch = {
      session_id: 'c1f1c6a2-0000-4000-8000-000000000000',
      council_id: COUNCIL,
      helper_slots: [1, 2],
      my_slot: 1,
      target_roster_version: 1,
      target_threshold: 2,
      chain: [wire],
      transfer_keys_done: false,
      escrows: [],
      remaining: 0,
    };

    const first = await handleCouncilReshareBatch(a.id, { batch });
    expect(first.keys?.keys.map((k) => k.recipient_slot)).toEqual([1, 2, 3]);
    expect((await handleCouncilReshareBatch(a.id, { batch: { ...batch, transfer_keys_done: true } })).keys).toBeNull();

    await expect(handleCouncilReshareBatch(a.id, { batch: { ...batch, target_roster_version: 2 } })).rejects.toMatchObject({
      code: VaultErrorCode.VAULT_INTEGRITY_FAILED,
    });
  });
});
