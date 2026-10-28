import 'fake-indexeddb/auto';
import { type Mock, beforeEach, describe, expect, it, vi } from 'vitest';

import { type RosterRecord, requestFingerprint, rosterHash, signRoster } from '@encryption/src/crypto/council';
import { escrowRecordFromWire } from '@encryption/src/crypto/council-protocol';
import { generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { base64ToUint8, exportPublicKeyAsBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { getEncryptionDB } from '@encryption/src/crypto/encryption-db';
import { mnemonicToKey } from '@encryption/src/crypto/mnemonic';
import { type SignatureKeyPair, generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import { signAuthPublicKeyBinding } from '@encryption/src/crypto/vault-unlock';
import { STORE_COUNCIL_VERIFIED } from '@encryption/src/shared/constants';
import type { CouncilEscrowBody, RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import { VaultErrorCode } from '@encryption/src/shared/vault-error';
import { handleFetchPublicKeys } from '@encryption/src/vault/operations/fetch-public-keys';
import { handleCheckFingerprints } from '@encryption/src/vault/operations/fingerprint-registry';
import { deriveKeyring, loadWithIdentity } from '@encryption/src/vault/operations/onboarding';
import {
  type CustodianRequestDetail,
  handleCheckCouncilEscrow,
  handleCheckCouncilShares,
  handleCouncilContribute,
  handleCouncilReshareBatch,
  handleCreateCouncilEscrow,
  handleMarkCouncilVerified,
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
  (handleCheckFingerprints as Mock).mockResolvedValue({ results: [] });
  await (await getEncryptionDB()).clear(STORE_COUNCIL_VERIFIED);
});

describe('council code and verification', () => {
  // v2 replaces c by d, signed by a and b (a majority of three) and by d.
  async function grown() {
    const v1 = await genesis([a, b, c], 2);
    const d = await person(5);
    const record: RosterRecord = {
      councilId: COUNCIL,
      version: 2,
      threshold: 2,
      previousRosterHash: await rosterHash(v1.record),
      members: [...v1.record.members.slice(0, 2), { slot: 4, userId: d.id, identityPublicKeyWire: base64ToUint8(wireB64(d.identity)) }],
    };
    const v2 = versionWire(
      record,
      await Promise.all([a, b, d].map(async (p) => ({ identity: p.identity, signature: await signRoster(record, p.identity.secretKey) })))
    );

    return { v1, v2 };
  }

  it('shows the code of version 1, which a later version does not change', async () => {
    const { v1, v2 } = await grown();

    const first = await handleVerifyCouncilRoster(ME, { councilId: COUNCIL, chain: [v1.wire] });
    const later = await handleVerifyCouncilRoster(ME, { councilId: COUNCIL, chain: [v1.wire, v2] });
    expect(later).toMatchObject({ version: 2, fingerprint: first.fingerprint, verified: false });
    expect(first.fingerprint).toMatch(/^1\d{39}$/);
  });

  it('is verified once the user compared the code, on this browser', async () => {
    const { v1, v2 } = await grown();

    expect(await handleMarkCouncilVerified(ME, { councilId: COUNCIL, chain: [v1.wire] })).toMatchObject({ verified: true });
    expect((await handleVerifyCouncilRoster(ME, { councilId: COUNCIL, chain: [v1.wire, v2] })).verified).toBe(true);
  });

  // The circle: every member of version 1 checked the next before signing, so
  // one real member the user verified vouches for the whole list.
  it('is verified through a custodian of version 1 the user verified, and only of version 1', async () => {
    const { v1, v2 } = await grown();
    (handleCheckFingerprints as Mock).mockImplementation(async (_u: string, { userFingerprints }: { userFingerprints: Record<string, string> }) => ({
      results: Object.keys(userFingerprints).map((id) => ({ userId: id, status: id === b.id ? 'trusted' : 'unknown' })),
    }));

    expect((await handleVerifyCouncilRoster(ME, { councilId: COUNCIL, chain: [v1.wire, v2] })).verified).toBe(true);
    // Only version 1's members are asked about: a newcomer never checked the others.
    expect(Object.keys((handleCheckFingerprints as Mock).mock.calls.at(-1)![1].userFingerprints).sort()).toEqual([a.id, b.id, c.id].sort());

    (handleCheckFingerprints as Mock).mockResolvedValue({ results: [{ userId: a.id, status: 'unknown' }] });
    expect((await handleVerifyCouncilRoster(ME, { councilId: COUNCIL, chain: [v1.wire, v2] })).verified).toBe(false);
  });

  it('refuses another council presented under the same id once one was verified', async () => {
    const { v1 } = await grown();
    await handleMarkCouncilVerified(ME, { councilId: COUNCIL, chain: [v1.wire] });
    const forged = await genesis([a, b, await person(9)], 2);

    await expect(handleVerifyCouncilRoster(ME, { councilId: COUNCIL, chain: [forged.wire] })).rejects.toMatchObject({
      code: VaultErrorCode.VAULT_INTEGRITY_FAILED,
    });
    await expect(handleMarkCouncilVerified(ME, { councilId: COUNCIL, chain: [forged.wire] })).rejects.toMatchObject({
      code: VaultErrorCode.VAULT_INTEGRITY_FAILED,
    });
  });

  it('marks nothing on a chain that does not verify', async () => {
    const { v1 } = await grown();

    await expect(
      handleMarkCouncilVerified(ME, { councilId: COUNCIL, chain: [{ ...v1.wire, signatures: v1.wire.signatures.slice(1) }] })
    ).rejects.toMatchObject({ code: VaultErrorCode.VAULT_INTEGRITY_FAILED });
    expect((await handleVerifyCouncilRoster(ME, { councilId: COUNCIL, chain: [v1.wire] })).verified).toBe(false);
  });

  it('reports the code and the verification with the escrow audit', async () => {
    const { v1 } = await grown();
    const body = await handleCreateCouncilEscrow(ME, { councilId: COUNCIL, chain: [v1.wire] });
    const record = await recordOf(body, v1.wire);
    const { fingerprint } = await handleVerifyCouncilRoster(ME, { councilId: COUNCIL, chain: [v1.wire] });

    expect(await handleCheckCouncilEscrow(ME, { record, chain: [v1.wire] })).toMatchObject({
      status: 'ok',
      council: { fingerprint, verified: false },
    });
    await handleMarkCouncilVerified(ME, { councilId: COUNCIL, chain: [v1.wire] });
    expect(await handleCheckCouncilEscrow(ME, { record, chain: [v1.wire] })).toMatchObject({ council: { fingerprint, verified: true } });
  });
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

  describe('renewal of the emergency secret', () => {
    // A version 2 of the council signed by a and b (a majority of three) and by
    // every member it adds or re-keys.
    async function next(v1: RosterRecord, members: RosterRecord['members'], newcomers: Person[]): Promise<RosterVersionWire> {
      const record: RosterRecord = { councilId: COUNCIL, version: 2, threshold: 2, previousRosterHash: await rosterHash(v1), members };
      const signers = [a, b, ...newcomers];

      return versionWire(
        record,
        await Promise.all(signers.map(async (p) => ({ identity: p.identity, signature: await signRoster(record, p.identity.secretKey) })))
      );
    }

    async function enrolled() {
      const v1 = await genesis([a, b, c], 2);
      const body = await handleCreateCouncilEscrow(ME, { councilId: COUNCIL, chain: [v1.wire] });

      return { v1, record: await recordOf(body, v1.wire) };
    }

    const keyOf = (p: Person) => base64ToUint8(wireB64(p.identity));

    it('is not due while every custodian of the split is still there', async () => {
      const { v1, record } = await enrolled();
      const d = await person(5);
      // Adding a custodian takes nothing from anyone: no renewal.
      const grown = await next(v1.record, [...v1.record.members, { slot: 4, userId: d.id, identityPublicKeyWire: keyOf(d) }], [d]);

      expect(await handleCheckCouncilEscrow(ME, { record, chain: [v1.wire] })).toMatchObject({ status: 'ok', renewalDue: false });
      expect(await handleCheckCouncilEscrow(ME, { record, chain: [v1.wire, grown] })).toMatchObject({ status: 'ok', renewalDue: false });
    });

    it('is due once a custodian of the split has left', async () => {
      const { v1, record } = await enrolled();
      const d = await person(5);
      const replaced = await next(v1.record, [...v1.record.members.slice(0, 2), { slot: 4, userId: d.id, identityPublicKeyWire: keyOf(d) }], [d]);

      expect(await handleCheckCouncilEscrow(ME, { record, chain: [v1.wire, replaced] })).toMatchObject({ status: 'ok', renewalDue: true });
    });

    it('is due once a custodian of the split changed identity key', async () => {
      const { v1, record } = await enrolled();
      const rekeyed = { ...c, identity: await generateSignatureKeyPair() };
      const members = v1.record.members.map((m) => (m.userId === c.id ? { ...m, slot: 5, identityPublicKeyWire: keyOf(rekeyed) } : m));

      expect(await handleCheckCouncilEscrow(ME, { record, chain: [v1.wire, await next(v1.record, members, [rekeyed])] })).toMatchObject({
        status: 'ok',
        renewalDue: true,
      });
    });

    it('is never due on an escrow or a chain that does not verify', async () => {
      const { v1, record } = await enrolled();

      expect(await handleCheckCouncilEscrow(ME, { record: { ...record, threshold: 1 }, chain: [v1.wire] })).toMatchObject({ renewalDue: false });
      expect(await handleCheckCouncilEscrow(ME, { record, chain: [{ ...v1.wire, threshold: 3 }] })).toMatchObject({ renewalDue: false });
    });

    it('is no longer due once the new secret is split on the current head', async () => {
      const { v1 } = await enrolled();
      const d = await person(5);
      const v2 = await next(v1.record, [...v1.record.members.slice(0, 2), { slot: 4, userId: d.id, identityPublicKeyWire: keyOf(d) }], [d]);
      (handleFetchPublicKeys as Mock).mockResolvedValue(directory([me, a, b, c, d]));

      const renewed = await handleCreateCouncilEscrow(ME, {
        councilId: COUNCIL,
        chain: [v1.wire, v2],
        anchorHash: (await enrolled()).record.roster_hash,
      });
      expect(renewed.roster_version).toBe(2);
      expect(renewed.shares.map((sh) => sh.slot)).toEqual([1, 2, 4]);

      const record = await recordOf(renewed, v2);
      expect(await handleCheckCouncilEscrow(ME, { record, chain: [v1.wire, v2] })).toMatchObject({ status: 'ok', renewalDue: false });
    });
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
        chain: [wire],
        attestation: null as CustodianRequestDetail['attestation'],
      },
      body,
      code: await requestFingerprint(base64ToUint8(exportPublicKeyAsBase64(ephemeral.publicKey))),
    };
  }

  it('hands the share over in person to the key whose code was read', async () => {
    const { detail, code } = await requestFor(a);

    expect((await handleCouncilContribute(a.id, { detail, inPerson: true, meetingCode: code.replace(/(\d{5})/g, '$1 ') })).in_person).toBe(true);
  });

  describe('remotely, only after the meeting', () => {
    // b meets the person and hands over in person: the signed share is the attestation.
    async function metBy(attester: Person) {
      const { detail, code, body } = await requestFor(attester);
      const handed = await handleCouncilContribute(attester.id, { detail, inPerson: true, meetingCode: code });
      const attestation = { slot: handed.slot, custodian_user_id: attester.id, wrapped_share: handed.wrapped_share, signature: handed.signature };

      // a's view of the same request.
      loadAs(a);
      return { detail: { ...detail, capsule: { ...detail.capsule, slot: 1, wrapped_share: body.shares[0].wrapped_share } }, attestation };
    }

    it('releases a remote share to a key another custodian attested in person', async () => {
      const { detail, attestation } = await metBy(b);

      expect((await handleCouncilContribute(a.id, { detail: { ...detail, attestation }, inPerson: false })).in_person).toBe(false);
    });

    it('refuses a remote share before anyone met the person', async () => {
      const { detail } = await metBy(b);

      await expect(handleCouncilContribute(a.id, { detail, inPerson: false })).rejects.toMatchObject({ code: VaultErrorCode.COUNCIL_MEETING_FIRST });
    });

    // The server's own request: it can make up a key, never a custodian's signature over it.
    it('refuses an attestation of another key, a forged one, one by a stranger, or one by the caller', async () => {
      const { detail, attestation } = await metBy(b);
      const otherKey = exportPublicKeyAsBase64((await generateUserKeyPair()).publicKey);
      const stranger = await person(9);
      const refused = async (changed: Partial<CustodianRequestDetail>) =>
        expect(handleCouncilContribute(a.id, { detail: { ...detail, attestation, ...changed }, inPerson: false })).rejects.toMatchObject({
          code: VaultErrorCode.COUNCIL_MEETING_FIRST,
        });

      await refused({ ephemeral_public_key: otherKey });
      await refused({ attestation: { ...attestation, signature: uint8ToBase64(new Uint8Array(64)) } });
      await refused({ attestation: { ...attestation, custodian_user_id: stranger.id } });
      await refused({ attestation: { ...attestation, slot: 3 } });
      await refused({ attestation: { ...attestation, custodian_user_id: a.id } });
      await refused({ id: 'b9f1c6a2-0000-4000-8000-000000000001' });
    });

    it('refuses an attestation that was not handed over in person', async () => {
      const { detail, code } = await requestFor(b);
      // A remote share by b, made as if b had been attested: its record says remote.
      const fake = await handleCouncilContribute(b.id, { detail, inPerson: true, meetingCode: code });
      const { signContribution, ephemeralKeyHash: hashKey, wrappedSharesHash: hashShares } = await import('@encryption/src/crypto/council');
      const remoteSignature = await signContribution(
        {
          requestId: detail.id,
          userId: ME,
          councilId: COUNCIL,
          slot: 2,
          custodianUserId: b.id,
          ephemeralPublicKeyHash: await hashKey(base64ToUint8(detail.ephemeral_public_key)),
          wrappedSharesHash: await hashShares([base64ToUint8(fake.wrapped_share)]),
          inPerson: false,
        },
        b.identity.secretKey
      );
      loadAs(a);

      await expect(
        handleCouncilContribute(a.id, {
          detail: {
            ...detail,
            capsule: { ...detail.capsule, slot: 1 },
            attestation: { slot: 2, custodian_user_id: b.id, wrapped_share: fake.wrapped_share, signature: uint8ToBase64(remoteSignature) },
          },
          inPerson: false,
        })
      ).rejects.toMatchObject({ code: VaultErrorCode.COUNCIL_MEETING_FIRST });
    });
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
    const { detail, code } = await requestFor(a);
    loadAs(me);
    const { wire } = await genesis([a, b, c], 2);
    const other = await handleCreateCouncilEscrow(ME, { councilId: COUNCIL, chain: [wire] });
    loadAs(a);

    await expect(
      handleCouncilContribute(a.id, {
        detail: { ...detail, capsule: { kind: 'direct', generation: 1, slot: 1, wrapped_share: other.shares[0].wrapped_share } },
        inPerson: true,
        meetingCode: code,
      })
    ).rejects.toMatchObject({ code: VaultErrorCode.VAULT_INTEGRITY_FAILED });
  });

  it('refuses a slot the verified council does not give this custodian', async () => {
    const { detail, code } = await requestFor(a);

    await expect(
      handleCouncilContribute(a.id, { detail: { ...detail, capsule: { ...detail.capsule, slot: 2 } }, inPerson: true, meetingCode: code })
    ).rejects.toMatchObject({ code: VaultErrorCode.VAULT_INTEGRITY_FAILED });
  });

  it('refuses malformed data from the server before touching any key', async () => {
    const { detail, code } = await requestFor(a);

    await expect(
      handleCouncilContribute(a.id, { detail: { ...detail, capsule: { ...detail.capsule, slot: 0 } }, inPerson: true, meetingCode: code })
    ).rejects.toMatchObject({ code: VaultErrorCode.VAULT_INTEGRITY_FAILED, message: expect.stringContaining('malformed') });
  });

  it('refuses an escrow the person asking did not sign', async () => {
    const { detail, code } = await requestFor(b);

    await expect(
      handleCouncilContribute(b.id, { detail: { ...detail, escrow: { ...detail.escrow, threshold: 1 } }, inPerson: true, meetingCode: code })
    ).rejects.toMatchObject({
      code: VaultErrorCode.VAULT_INTEGRITY_FAILED,
    });
    // The signed record itself is genuine.
    expect(escrowRecordFromWire(ME, detail.escrow).threshold).toBe(2);
  });
});

describe('checking received shares', () => {
  it('judges each share against the signed commitments, and skips a record the owner did not sign', async () => {
    const { wire } = await genesis([a, b, c], 2);
    const body = await handleCreateCouncilEscrow(ME, { councilId: COUNCIL, chain: [wire] });
    const other = await handleCreateCouncilEscrow(ME, { councilId: COUNCIL, chain: [wire] });
    const record = await recordOf(body, wire);
    loadAs(a);

    const entry = (escrowId: string, wrapped: string, signedRecord = record) => ({
      escrow_id: escrowId,
      user_id: ME,
      record: signedRecord,
      capsule: { kind: 'direct' as const, generation: 1, slot: 1, wrapped_share: wrapped },
    });
    const ids = ['e5c0e5c0-0000-4000-8000-000000000001', 'e5c0e5c0-0000-4000-8000-000000000002', 'e5c0e5c0-0000-4000-8000-000000000003'];

    const { results } = await handleCheckCouncilShares(a.id, {
      batch: {
        council_id: COUNCIL,
        chain: [wire],
        remaining: 3,
        escrows: [
          entry(ids[0], body.shares[0].wrapped_share),
          entry(ids[1], other.shares[0].wrapped_share),
          entry(ids[2], body.shares[0].wrapped_share, { ...record, threshold: 1 }),
        ],
      },
    });

    expect(results).toEqual([
      { escrow_id: ids[0], valid: true, faulty_helper_slot: null },
      { escrow_id: ids[1], valid: false, faulty_helper_slot: null },
    ]);
  });
});

describe('signing a roster', () => {
  it('signs a first version that names me with my own key, once the next member is checked', async () => {
    loadAs(a);
    const { record } = await genesis([a, b, c], 2);
    const sign = () => handleSignCouncilRoster(a.id, { councilId: COUNCIL, chain: [], proposal: versionWire(record, []) });

    (handleCheckFingerprints as Mock).mockResolvedValue({ results: [{ userId: b.id, status: 'unknown' }] });
    await expect(sign()).rejects.toMatchObject({ code: VaultErrorCode.UNTRUSTED_RECIPIENT });

    (handleCheckFingerprints as Mock).mockResolvedValue({ results: [{ userId: b.id, status: 'trusted' }] });
    expect((await sign()).signature).toBeTruthy();
    // a (slot 1) vouches for b (slot 2) only.
    expect(Object.keys((handleCheckFingerprints as Mock).mock.calls.at(-1)![1].userFingerprints)).toEqual([b.id]);
  });

  // The attack the circle stops: real custodians would otherwise sign a first
  // version in which the server put its own keys under familiar names.
  it('makes the last member check the first, closing the circle', async () => {
    loadAs(c);
    const { record } = await genesis([a, b, c], 2);
    (handleCheckFingerprints as Mock).mockResolvedValue({ results: [{ userId: a.id, status: 'trusted' }] });

    await handleSignCouncilRoster(c.id, { councilId: COUNCIL, chain: [], proposal: versionWire(record, []) });
    expect(Object.keys((handleCheckFingerprints as Mock).mock.calls.at(-1)![1].userFingerprints)).toEqual([a.id]);
  });

  it('refuses to sign a first version that does not name me', async () => {
    loadAs(me);
    const { record } = await genesis([a, b, c], 2);

    await expect(handleSignCouncilRoster(ME, { councilId: COUNCIL, chain: [], proposal: versionWire(record, []) })).rejects.toMatchObject({
      code: VaultErrorCode.VAULT_INTEGRITY_FAILED,
    });
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

  it('forgets its request key once the open request is not the one it opened', async () => {
    const { handleCouncilRequestKey } = await import('@encryption/src/vault/operations/recovery-council');
    const started = await handleStartCouncilRequest(ME);

    expect(await handleCouncilRequestKey(ME, { serverFingerprint: started.fingerprint })).toMatchObject({ fingerprint: started.fingerprint });
    expect(await handleCouncilRequestKey(ME, { serverFingerprint: '1'.repeat(40) })).toBeNull();
    expect(await handleCouncilRequestKey(ME)).toBeNull();
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

  // A reload loses nothing: the keys derive from the VRK, so the server never
  // has to take a second set from the same helper.
  it('derives the same transfer keys after a reload', async () => {
    loadAs(a);
    const { wire } = await genesis([a, b, c], 2);
    const { default: sodium } = await import('libsodium-wrappers-sumo');
    const { openTransferKey } = await import('@encryption/src/crypto/council');
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

    const [first, second] = [(await handleCouncilReshareBatch(a.id, { batch })).keys!, (await handleCouncilReshareBatch(a.id, { batch })).keys!];
    const forB = (keys: typeof first) => openTransferKey(base64ToUint8(keys.keys[1].wrapped_transfer_key), [b.kem.secretKey]);

    expect(sodium.to_hex(await forB(first))).toBe(sodium.to_hex(await forB(second)));
  });

  // The attack this guards against: a server shows honest helpers a chain it
  // made up (its own genesis, its own keys), and collects their sub-shares.
  it('refuses to reshare onto a chain that does not name this helper', async () => {
    loadAs(a);
    const [x, y] = await Promise.all([person(8), person(9)]);
    const { wire: forged } = await genesis([x, y, b], 2);
    (handleFetchPublicKeys as Mock).mockResolvedValue(directory([me, a, b, c, x, y]));

    const batch = {
      session_id: 'c1f1c6a2-0000-4000-8000-000000000000',
      council_id: COUNCIL,
      helper_slots: [1, 2],
      my_slot: 1,
      target_roster_version: 1,
      target_threshold: 2,
      chain: [forged],
      transfer_keys_done: false,
      escrows: [],
      remaining: 0,
    };

    await expect(handleCouncilReshareBatch(a.id, { batch })).rejects.toMatchObject({
      code: VaultErrorCode.VAULT_INTEGRITY_FAILED,
      message: expect.stringContaining('helper'),
    });
    await expect(
      handleCouncilReshareBatch(a.id, { batch: { ...batch, chain: [(await genesis([a, b, c], 2)).wire], helper_slots: [2, 3] } })
    ).rejects.toMatchObject({
      code: VaultErrorCode.VAULT_INTEGRITY_FAILED,
    });
  });
});
