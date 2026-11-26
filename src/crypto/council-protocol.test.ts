import { beforeAll, describe, expect, it } from 'vitest';

import { type RosterRecord, capsuleHash, rosterHash, signRoster } from '@encryption/src/crypto/council';
import {
  CouncilShareError,
  buildContribution,
  buildCouncilEscrow,
  buildReshareKeys,
  buildReshareSubShares,
  escrowRecordFromWire,
  openCustodianShare,
  recoverCouncilSecret,
} from '@encryption/src/crypto/council-protocol';
import { type HybridKeyPair, ensureSodium, generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { base64ToUint8, exportPublicKeyAsBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { randomScalar } from '@encryption/src/crypto/shamir';
import { type SignatureKeyPair, generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import type {
  CouncilCapsuleWire,
  CouncilEscrowBody,
  CouncilEscrowRecordWire,
  CouncilReleasedShares,
  RosterVersionWire,
} from '@encryption/src/shared/schemas/recovery-council';

const COUNCIL = 'dinum';

interface Person {
  id: string;
  identity: SignatureKeyPair;
  kem: HybridKeyPair;
  wire: Uint8Array;
}

async function person(n: number): Promise<Person> {
  const identity = await generateSignatureKeyPair();

  return {
    id: `${n}`.repeat(8) + '-0000-4000-8000-000000000000',
    identity,
    kem: await generateUserKeyPair(),
    wire: base64ToUint8(exportPublicKeyAsBase64(identity.publicKey)),
  };
}

async function signedWire(record: RosterRecord, signers: Person[]): Promise<RosterVersionWire> {
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
    signatures: await Promise.all(
      signers.map(async (p) => ({
        identity_public_key: uint8ToBase64(p.wire),
        signature: uint8ToBase64(await signRoster(record, p.identity.secretKey)),
      }))
    ),
  };
}

const credential = {
  wrapped_vrk: uint8ToBase64(new Uint8Array(48)),
  auth_public_key: uint8ToBase64(new Uint8Array(32).fill(7)),
  auth_pub_sig: uint8ToBase64(new Uint8Array(64)),
  kdf_ops: 3,
  kdf_mem: 64 * 1024 * 1024,
  lang: 'english' as const,
};

async function escrowFor(user: Person, head: RosterRecord, custodians: Person[], secret = randomScalar()) {
  const body = await buildCouncilEscrow({
    userId: user.id,
    head,
    custodianKeys: new Map(head.members.map((m) => [m.slot, custodians.find((c) => c.id === m.userId)!.kem.publicKey])),
    secret,
    credential,
    identitySecretKey: user.identity.secretKey,
    createdAtMillis: 1_700_000_000_000,
  });

  return { body, secret, record: await recordWire(body, head) };
}

async function recordWire(body: CouncilEscrowBody, head: RosterRecord): Promise<CouncilEscrowRecordWire> {
  const { default: sodium } = await import('libsodium-wrappers-sumo');

  return {
    council_id: body.council_id,
    roster_version: body.roster_version,
    roster_hash: uint8ToBase64(await rosterHash(head)),
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

const direct = (body: CouncilEscrowBody, slot: number): CouncilCapsuleWire => ({
  kind: 'direct',
  generation: 1,
  slot,
  wrapped_share: body.shares.find((s) => s.slot === slot)!.wrapped_share,
});

let a: Person;
let b: Person;
let c: Person;
let d: Person;
let ursula: Person;
let victor: Person;
let v1: RosterRecord;
let v1Wire: RosterVersionWire;

beforeAll(async () => {
  await ensureSodium();
  [a, b, c, d, ursula, victor] = await Promise.all([1, 2, 3, 4, 5, 6].map(person));
  v1 = {
    councilId: COUNCIL,
    version: 1,
    threshold: 2,
    previousRosterHash: new Uint8Array(0),
    members: [a, b, c].map((p, i) => ({ slot: i + 1, userId: p.id, identityPublicKeyWire: p.wire })),
  };
  v1Wire = await signedWire(v1, [a, b, c]);
});

describe('a custodian’s capsule', () => {
  it('opens only as the share of the person whose signed record names it', async () => {
    const victim = await escrowFor(victor, v1, [a, b, c]);
    const context = { councilId: COUNCIL, versions: [v1], secretKeys: [a.kem.secretKey] };

    expect(await openCustodianShare(direct(victim.body, 1), escrowRecordFromWire(victor.id, victim.record), context)).toHaveLength(65);

    // A record of Ursula's (her vault would sign it) copying Victor's split: his capsule still does not open as hers.
    const forged = escrowRecordFromWire(ursula.id, victim.record);
    await expect(openCustodianShare(direct(victim.body, 1), forged, context)).rejects.toBeInstanceOf(CouncilShareError);

    // Nor a capsule the record does not list.
    const other = await escrowFor(victor, v1, [a, b, c]);
    await expect(openCustodianShare(direct(other.body, 1), escrowRecordFromWire(victor.id, victim.record), context)).rejects.toThrow(
      'not the one the user signed'
    );
  });
});

describe('a reshared capsule', () => {
  async function reshared(owner: Person) {
    const escrow = await escrowFor(owner, v1, [a, b, c]);
    const v2: RosterRecord = {
      councilId: COUNCIL,
      version: 2,
      threshold: 2,
      previousRosterHash: await rosterHash(v1),
      members: [
        { slot: 1, userId: a.id, identityPublicKeyWire: a.wire },
        { slot: 2, userId: b.id, identityPublicKeyWire: b.wire },
        { slot: 4, userId: d.id, identityPublicKeyWire: d.wire },
      ],
    };
    const sessionId = '0b7e5f0c-5c8e-4c1a-9d3b-1f2e3d4c5b6a';
    const escrowId = '6f2d4c1a-5c8e-4c1a-9d3b-1f2e3d4c5b6a';
    const record = escrowRecordFromWire(owner.id, escrow.record);
    const helpers = [];

    for (const helper of [a, b]) {
      const slot = v1.members.find((m) => m.userId === helper.id)!.slot;
      const target = {
        sessionId,
        councilId: COUNCIL,
        target: v2,
        helperSlots: [1, 2],
        mySlot: slot,
        vrk: new Uint8Array(32).fill(slot),
        identitySecretKey: helper.identity.secretKey,
      };
      const share = await openCustodianShare(direct(escrow.body, slot), record, {
        councilId: COUNCIL,
        versions: [v1],
        secretKeys: [helper.kem.secretKey],
      });
      const { body: keys, transferKeys } = await buildReshareKeys({
        ...target,
        recipientKeys: new Map([
          [1, a.kem.publicKey],
          [2, b.kem.publicKey],
          [4, d.kem.publicKey],
        ]),
      });
      const subShares = await buildReshareSubShares(target, transferKeys, { id: escrowId, userId: owner.id }, share);
      const key = keys.keys.find((k) => k.recipient_slot === 4)!;
      helpers.push({
        helper_slot: slot,
        helper_identity_public_key: uint8ToBase64(helper.wire),
        wrapped_transfer_key: key.wrapped_transfer_key,
        binding_signature: key.binding_signature,
        sealed_sub_share: subShares.sub_shares.find((s) => s.recipient_slot === 4)!.sealed,
        commitments: subShares.commitments,
        commitments_signature: subShares.commitments_signature,
      });
    }

    const capsule: CouncilCapsuleWire = {
      kind: 'reshared',
      generation: 2,
      slot: 4,
      session_id: sessionId,
      escrow_id: escrowId,
      target_roster_version: 2,
      helpers,
    };

    return { capsule, record, v2, context: { councilId: COUNCIL, versions: [v1, v2], secretKeys: [d.kem.secretKey] } };
  }

  it('opens for the newcomer as the sum of its helpers’ sub-shares', async () => {
    const { capsule, record, context } = await reshared(victor);

    expect(await openCustodianShare(capsule, record, context)).toHaveLength(65);
  });

  it('does not open as another person’s share, and names the helper whose part fails', async () => {
    const { capsule, record, context } = await reshared(victor);
    const ursulas = { ...record, userId: ursula.id };
    await expect(openCustodianShare(capsule, ursulas, context)).rejects.toMatchObject({ helperSlot: 1 });

    const swapped = { ...capsule, helpers: [capsule.helpers[0], { ...capsule.helpers[1], sealed_sub_share: capsule.helpers[0].sealed_sub_share }] };
    await expect(openCustodianShare(swapped, record, context)).rejects.toMatchObject({ name: 'CouncilShareError', helperSlot: 2 });
  });
});

describe('the locked-out browser', () => {
  async function released(options: { inPerson?: boolean[]; chain?: RosterVersionWire[] } = {}) {
    const escrow = await escrowFor(ursula, v1, [a, b, c]);
    const ephemeral = await generateUserKeyPair();
    const ephemeralWire = base64ToUint8(exportPublicKeyAsBase64(ephemeral.publicKey));
    const record = escrowRecordFromWire(ursula.id, escrow.record);
    const requestId = '9a8b7c6d-5c8e-4c1a-9d3b-1f2e3d4c5b6a';

    const contributions = await Promise.all(
      [a, b, c].map(async (custodian, i) => {
        const slot = i + 1;
        const share = await openCustodianShare(direct(escrow.body, slot), record, {
          councilId: COUNCIL,
          versions: [v1],
          secretKeys: [custodian.kem.secretKey],
        });
        const inPerson = options.inPerson?.[i] ?? i === 0;
        const body = await buildContribution({
          requestId,
          userId: ursula.id,
          councilId: COUNCIL,
          slot,
          custodianUserId: custodian.id,
          ephemeralPublicKey: ephemeralWire,
          encodedShare: share,
          inPerson,
          identitySecretKey: custodian.identity.secretKey,
        });

        return {
          slot,
          wrapped_share: body.wrapped_share,
          in_person: inPerson,
          signature: body.signature,
          custodian_user_id: custodian.id,
          custodian_name: null,
        };
      })
    );

    const shares: CouncilReleasedShares = {
      request_id: requestId,
      council_id: COUNCIL,
      user_id: ursula.id,
      owner_identity_public_key: uint8ToBase64(ursula.wire),
      generation: 1,
      threshold: 2,
      share_commitments: escrow.record.share_commitments,
      lang: 'english',
      escrow: escrow.record,
      chain: options.chain ?? [v1Wire],
      contributions,
    };

    return { shares, ephemeral: { publicKey: ephemeralWire, secretKey: ephemeral.secretKey }, secret: escrow.secret };
  }

  it('rebuilds the secret from shares the verified council handed over, one of them in person', async () => {
    const { shares, ephemeral, secret } = await released();

    const recovered = await recoverCouncilSecret(shares, ephemeral, ursula.wire);
    expect(recovered.secret).toEqual(secret);
    expect(recovered.contributors[0]).toMatchObject({ slot: 1, inPerson: true });
  });

  it('counts one share per slot', async () => {
    const { shares, ephemeral, secret } = await released();
    const doubled = { ...shares, contributions: [shares.contributions[0], shares.contributions[0], shares.contributions[1]] };

    expect((await recoverCouncilSecret(doubled, ephemeral, ursula.wire)).secret).toEqual(secret);
  });

  it('refuses shares signed by keys the council does not name, whoever the server says signed them', async () => {
    const { shares, ephemeral } = await released();
    // The server swaps a custodian for a stranger at slot 2: that contribution no longer counts.
    const stranger = { ...shares.contributions[1], custodian_user_id: d.id };

    await expect(recoverCouncilSecret({ ...shares, contributions: [shares.contributions[0], stranger] }, ephemeral, ursula.wire)).rejects.toThrow(
      'Not enough valid shares'
    );
  });

  it('refuses a recovery where nobody met the person', async () => {
    const { shares, ephemeral } = await released({ inPerson: [false, false, false] });

    await expect(recoverCouncilSecret(shares, ephemeral, ursula.wire)).rejects.toThrow('in person');
  });

  it('refuses a chain that does not reach the version the escrow pins', async () => {
    const stranger = await signedWire({ ...v1, members: [a, b, d].map((p, i) => ({ slot: i + 1, userId: p.id, identityPublicKeyWire: p.wire })) }, [
      a,
      b,
      d,
    ]);
    const { shares, ephemeral } = await released({ chain: [stranger] });

    await expect(recoverCouncilSecret(shares, ephemeral, ursula.wire)).rejects.toThrow('could not be verified');
  });
});
