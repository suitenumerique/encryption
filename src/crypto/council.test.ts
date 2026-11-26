import sodium from 'libsodium-wrappers-sumo';
import { describe, expect, it } from 'vitest';

import {
  type CouncilEscrowRecord,
  type RosterMember,
  type RosterRecord,
  type SignedRosterVersion,
  councilFingerprint,
  deriveTransferKey,
  encodeContributionPayload,
  encodeEscrowPayload,
  encodeReshareCommitments,
  encodeReshareKeyBinding,
  encodeRosterPayload,
  openSubShare,
  openTransferKey,
  requestFingerprint,
  rosterFingerprint,
  rosterHash,
  sealSubShare,
  secretCommitment,
  signContribution,
  signEscrow,
  signReshareCommitments,
  signReshareKeyBinding,
  signRoster,
  unwrapCapsule,
  unwrapRequestShare,
  verifyContribution,
  verifyEscrow,
  verifyReshareCommitments,
  verifyReshareKeyBinding,
  verifyRosterChain,
  wrapShareForCustodian,
  wrapShareForRequest,
  wrapTransferKey,
} from '@encryption/src/crypto/council';
import { ensureSodium, generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { base64ToUint8, exportPublicKeyAsBase64 } from '@encryption/src/crypto/encryption-backup';
import { encodeShare, randomScalar, splitSecret } from '@encryption/src/crypto/shamir';
import { type SignatureKeyPair, generateSignatureKeyPair } from '@encryption/src/crypto/signature';

const COUNCIL = 'dinum';

interface Person {
  userId: string;
  identity: SignatureKeyPair;
  wire: Uint8Array;
}

async function person(n: number): Promise<Person> {
  const identity = await generateSignatureKeyPair();

  return { userId: `${n}`.repeat(8) + '-0000-4000-8000-000000000000', identity, wire: base64ToUint8(exportPublicKeyAsBase64(identity.publicKey)) };
}

function member(p: Person, slot: number): RosterMember {
  return { slot, userId: p.userId, identityPublicKeyWire: p.wire };
}

async function signedBy(record: RosterRecord, signers: Person[]): Promise<SignedRosterVersion> {
  return {
    record,
    signatures: await Promise.all(
      signers.map(async (p) => ({ identityPublicKeyWire: p.wire, signature: await signRoster(record, p.identity.secretKey) }))
    ),
  };
}

async function genesis(people: Person[], threshold: number): Promise<RosterRecord> {
  return { councilId: COUNCIL, version: 1, threshold, previousRosterHash: new Uint8Array(0), members: people.map((p, i) => member(p, i + 1)) };
}

describe('roster chain', () => {
  it('accepts a genesis signed by every member, and refuses it with one missing', async () => {
    const [a, b, c] = await Promise.all([person(1), person(2), person(3)]);
    const v1 = await genesis([a, b, c], 2);

    expect((await verifyRosterChain([await signedBy(v1, [a, b, c])])).ok).toBe(true);
    expect(await verifyRosterChain([await signedBy(v1, [a, b])])).toMatchObject({ ok: false, reason: 'genesis-unsigned' });
  });

  it('refuses a genesis signed by a key that is not the member’s own', async () => {
    const [a, b, intruder] = await Promise.all([person(1), person(2), person(9)]);
    const v1 = await genesis([a, b], 1);
    const forged: SignedRosterVersion = {
      record: v1,
      signatures: [
        { identityPublicKeyWire: a.wire, signature: await signRoster(v1, a.identity.secretKey) },
        { identityPublicKeyWire: b.wire, signature: await signRoster(v1, intruder.identity.secretKey) },
      ],
    };

    expect((await verifyRosterChain([forged])).ok).toBe(false);
  });

  it('refuses one identity key on two slots (its signature would count twice)', async () => {
    const [a, b] = await Promise.all([person(1), person(2)]);
    const v1: RosterRecord = { ...(await genesis([a, b], 2)), members: [member(a, 1), member(b, 2), { ...member(a, 3), userId: 'other-user' }] };

    expect(await verifyRosterChain([await signedBy(v1, [a, b])])).toMatchObject({ ok: false, reason: 'bad-genesis' });
  });

  it('accepts a replacement signed by a majority of the previous version and the newcomer', async () => {
    const [a, b, c, d, g] = await Promise.all([person(1), person(2), person(3), person(4), person(7)]);
    const v1 = await genesis([a, b, c, d], 2);
    const v2: RosterRecord = {
      councilId: COUNCIL,
      version: 2,
      threshold: 2,
      previousRosterHash: await rosterHash(v1),
      members: [member(a, 1), member(b, 2), member(c, 3), member(g, 5)],
    };
    const chain = [await signedBy(v1, [a, b, c, d]), await signedBy(v2, [a, b, c, g])];

    const result = await verifyRosterChain(chain);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.head.version).toBe(2);
  });

  it('refuses a version without the quorum of the previous one (a server cannot forge one)', async () => {
    const [a, b, c, d, g] = await Promise.all([person(1), person(2), person(3), person(4), person(7)]);
    const v1 = await genesis([a, b, c, d], 2);
    const v2: RosterRecord = {
      councilId: COUNCIL,
      version: 2,
      threshold: 1,
      previousRosterHash: await rosterHash(v1),
      members: [member(a, 1), member(g, 5)],
    };

    expect(await verifyRosterChain([await signedBy(v1, [a, b, c, d]), await signedBy(v2, [a, g])])).toMatchObject({ reason: 'no-quorum' });
    // k of the previous version is enough for a recovery, not for a change: that takes a majority.
    expect(await verifyRosterChain([await signedBy(v1, [a, b, c, d]), await signedBy(v2, [a, b, g])])).toMatchObject({ reason: 'no-quorum' });
  });

  it('refuses a newcomer who did not vouch for their own key', async () => {
    const [a, b, g] = await Promise.all([person(1), person(2), person(7)]);
    const v1 = await genesis([a, b], 1);
    const v2: RosterRecord = {
      councilId: COUNCIL,
      version: 2,
      threshold: 1,
      previousRosterHash: await rosterHash(v1),
      members: [member(a, 1), member(b, 2), member(g, 3)],
    };

    expect(await verifyRosterChain([await signedBy(v1, [a, b]), await signedBy(v2, [a, b])])).toMatchObject({ reason: 'newcomer-unsigned' });
  });

  it('refuses a slot given to someone else (that would hand over the old share)', async () => {
    const [a, b, c, g] = await Promise.all([person(1), person(2), person(3), person(7)]);
    const v1 = await genesis([a, b, c], 2);
    const v2: RosterRecord = {
      councilId: COUNCIL,
      version: 2,
      threshold: 2,
      previousRosterHash: await rosterHash(v1),
      members: [member(a, 1), member(b, 2), member(g, 3)],
    };

    expect(await verifyRosterChain([await signedBy(v1, [a, b, c]), await signedBy(v2, [a, b, g])])).toMatchObject({ reason: 'slot-reused' });
  });

  it('refuses a broken link, a skipped version and another council', async () => {
    const [a, b] = await Promise.all([person(1), person(2)]);
    const v1 = await genesis([a, b], 1);
    const base = { councilId: COUNCIL, version: 2, threshold: 1, previousRosterHash: await rosterHash(v1), members: [member(a, 1), member(b, 2)] };
    const s1 = await signedBy(v1, [a, b]);

    expect((await verifyRosterChain([s1, await signedBy({ ...base, previousRosterHash: new Uint8Array(32) }, [a])])).ok).toBe(false);
    expect((await verifyRosterChain([s1, await signedBy({ ...base, version: 3 }, [a])])).ok).toBe(false);
    expect((await verifyRosterChain([s1, await signedBy({ ...base, councilId: 'other' }, [a])])).ok).toBe(false);
  });

  it('verifies from a trusted anchor without re-checking what came before it', async () => {
    const [a, b, c] = await Promise.all([person(1), person(2), person(3)]);
    const v1 = await genesis([a, b], 1);
    const v2: RosterRecord = {
      councilId: COUNCIL,
      version: 2,
      threshold: 1,
      previousRosterHash: await rosterHash(v1),
      members: [member(a, 1), member(b, 2), member(c, 3)],
    };
    // v1 is deliberately unsigned: the anchor stands for it.
    const chain = [{ record: v1, signatures: [] }, await signedBy(v2, [a, b, c])];

    expect((await verifyRosterChain(chain, await rosterHash(v1))).ok).toBe(true);
    expect(await verifyRosterChain(chain, new Uint8Array(32))).toMatchObject({ reason: 'anchor-not-found' });
  });

  it('gives one fingerprint per roster, sensitive to every member key', async () => {
    const [a, b, x] = await Promise.all([person(1), person(2), person(9)]);
    const v1 = await genesis([a, b], 1);
    const swapped = { ...v1, members: [member(a, 1), member(x, 2)] };

    expect(await rosterFingerprint(v1)).toMatch(/^1\d{39}$/);
    expect(await rosterFingerprint(v1)).not.toBe(await rosterFingerprint(swapped));
    // Member order does not matter, slots do.
    expect(encodeRosterPayload({ ...v1, members: [...v1.members].reverse() })).toEqual(encodeRosterPayload(v1));
  });
});

describe('escrow record', () => {
  it('signs what was split and detects any change', async () => {
    const user = await person(5);
    const record: CouncilEscrowRecord = {
      userId: user.userId,
      councilId: COUNCIL,
      rosterVersion: 3,
      rosterHash: new Uint8Array(32).fill(1),
      threshold: 2,
      escrowCreatedAtMillis: 1_760_000_000_000,
      credentialAuthPublicKeyHash: new Uint8Array(32).fill(2),
      secretCommitment: new Uint8Array(32).fill(3),
      shareCommitments: new Uint8Array(64).fill(4),
      shares: [
        { slot: 2, capsuleHash: new Uint8Array(32).fill(5) },
        { slot: 1, capsuleHash: new Uint8Array(32).fill(7) },
      ],
    };
    const signature = await signEscrow(record, user.identity.secretKey);

    expect(await verifyEscrow(record, signature, user.wire)).toBe(true);
    expect(await verifyEscrow({ ...record, shares: [...record.shares].reverse() }, signature, user.wire)).toBe(true);
    expect(await verifyEscrow({ ...record, threshold: 1 }, signature, user.wire)).toBe(false);
    expect(await verifyEscrow({ ...record, rosterVersion: 4 }, signature, user.wire)).toBe(false);
    expect(await verifyEscrow({ ...record, shares: record.shares.slice(1) }, signature, user.wire)).toBe(false);
    expect(await verifyEscrow({ ...record, shareCommitments: new Uint8Array(64).fill(5) }, signature, user.wire)).toBe(false);
    expect(await verifyEscrow(record, signature, (await person(6)).wire)).toBe(false);
  });

  it('commits to the secret for one user and council', async () => {
    const secret = new Uint8Array(32).fill(9);
    const commitment = await secretCommitment('u', COUNCIL, secret);

    expect(commitment).toHaveLength(32);
    expect(await secretCommitment('u', COUNCIL, secret)).toEqual(commitment);
    expect(await secretCommitment('v', COUNCIL, secret)).not.toEqual(commitment);
    expect(await secretCommitment('u', 'other', secret)).not.toEqual(commitment);
  });
});

describe('wraps', () => {
  it('carries a share to its custodian, then to the locked-out browser', async () => {
    const [custodianOld, custodianNew, ephemeral] = await Promise.all([generateUserKeyPair(), generateUserKeyPair(), generateUserKeyPair()]);
    await ensureSodium();
    const [share] = splitSecret(randomScalar(), [4], 1).shares;
    const encoded = encodeShare(share);

    const binding = { userId: 'u', councilId: COUNCIL, slot: 4 };
    const capsule = await wrapShareForCustodian(encoded, custodianOld.publicKey, binding);
    // The custodian rotated since: the retained older key still opens it.
    expect(await unwrapCapsule(capsule, [custodianNew.secretKey, custodianOld.secretKey], binding)).toEqual(encoded);
    // Only as that person's share, of that council, at that slot.
    for (const other of [{ userId: 'v' }, { councilId: 'other' }, { slot: 5 }]) {
      await expect(unwrapCapsule(capsule, [custodianOld.secretKey], { ...binding, ...other })).rejects.toThrow();
    }

    const transfer = await wrapShareForRequest(encoded, ephemeral.publicKey);
    expect(await unwrapRequestShare(transfer, ephemeral.secretKey)).toEqual(encoded);

    // A capsule is not a transfer, and the other way round.
    await expect(unwrapRequestShare(capsule, custodianOld.secretKey)).rejects.toThrow();
    await expect(unwrapCapsule(transfer, [ephemeral.secretKey], binding)).rejects.toThrow();
  });

  it('shows the meeting code of an ephemeral key', async () => {
    const ephemeral = await generateUserKeyPair();
    expect(await requestFingerprint(ephemeral.publicKey)).toMatch(/^1\d{39}$/);
  });
});

describe('contribution', () => {
  it('signs the request, the wrapped shares and the in-person flag', async () => {
    const custodian = await person(1);
    const record = {
      requestId: 'r1',
      userId: 'u1',
      councilId: COUNCIL,
      slot: 2,
      custodianUserId: custodian.userId,
      ephemeralPublicKeyHash: new Uint8Array(32).fill(1),
      wrappedSharesHash: new Uint8Array(32).fill(2),
      inPerson: false,
    };
    const signature = await signContribution(record, custodian.identity.secretKey);

    expect(await verifyContribution(record, signature, custodian.wire)).toBe(true);
    expect(await verifyContribution({ ...record, inPerson: true }, signature, custodian.wire)).toBe(false);
    expect(await verifyContribution({ ...record, requestId: 'r2' }, signature, custodian.wire)).toBe(false);
  });
});

describe('resharing transfer', () => {
  it('seals sub-shares for one place only', async () => {
    const [helper, recipient] = await Promise.all([person(1), generateUserKeyPair()]);
    const transferKey = await deriveTransferKey(new Uint8Array(32).fill(1), {
      sessionId: 's',
      councilId: COUNCIL,
      targetRosterVersion: 2,
      recipientSlot: 5,
    });
    const wrapped = await wrapTransferKey(transferKey, recipient.publicKey);
    const where = { sessionId: 's', userId: 'u', escrowId: 'e', helperSlot: 1, recipientSlot: 5 };
    const subShare = new Uint8Array(32).fill(8);

    const sealed = await sealSubShare(transferKey, subShare, where);
    const opened = await openTransferKey(wrapped, [recipient.secretKey]);
    expect(await openSubShare(opened, sealed, where)).toEqual(subShare);
    await expect(openSubShare(opened, sealed, { ...where, escrowId: 'f' })).rejects.toThrow();
    await expect(openSubShare(opened, sealed, { ...where, userId: 'v' })).rejects.toThrow();
    await expect(openSubShare(opened, sealed, { ...where, recipientSlot: 6 })).rejects.toThrow();

    const binding = {
      sessionId: 's',
      councilId: COUNCIL,
      targetRosterVersion: 2,
      helperSlot: 1,
      recipientSlot: 5,
      wrappedTransferKeyHash: new Uint8Array(32),
    };
    const signature = await signReshareKeyBinding(binding, helper.identity.secretKey);
    expect(await verifyReshareKeyBinding(binding, signature, helper.wire)).toBe(true);
    expect(await verifyReshareKeyBinding({ ...binding, recipientSlot: 6 }, signature, helper.wire)).toBe(false);
  });

  it('derives the same transfer key again for one place, and another for any other', async () => {
    const vrk = new Uint8Array(32).fill(1);
    const where = { sessionId: 's', councilId: COUNCIL, targetRosterVersion: 2, recipientSlot: 5 };
    const key = await deriveTransferKey(vrk, where);

    expect(await deriveTransferKey(vrk, where)).toEqual(key);
    for (const other of [{ sessionId: 't' }, { councilId: 'other' }, { targetRosterVersion: 3 }, { recipientSlot: 6 }]) {
      expect(await deriveTransferKey(vrk, { ...where, ...other })).not.toEqual(key);
    }
    expect(await deriveTransferKey(new Uint8Array(32).fill(2), where)).not.toEqual(key);
  });

  it('signs the commitments of one helper for one escrow of one session', async () => {
    const helper = await person(1);
    const record = {
      sessionId: 's',
      councilId: COUNCIL,
      userId: 'u',
      escrowId: 'e',
      targetRosterVersion: 2,
      helperSlot: 1,
      commitments: new Uint8Array(64).fill(3),
    };
    const signature = await signReshareCommitments(record, helper.identity.secretKey);

    expect(await verifyReshareCommitments(record, signature, helper.wire)).toBe(true);
    expect(await verifyReshareCommitments({ ...record, escrowId: 'f' }, signature, helper.wire)).toBe(false);
    expect(await verifyReshareCommitments({ ...record, userId: 'v' }, signature, helper.wire)).toBe(false);
    expect(await verifyReshareCommitments({ ...record, helperSlot: 2 }, signature, helper.wire)).toBe(false);
    expect(await verifyReshareCommitments({ ...record, commitments: new Uint8Array(64).fill(4) }, signature, helper.wire)).toBe(false);
    expect(await verifyReshareCommitments(record, signature, (await person(2)).wire)).toBe(false);
  });
});

// Frozen bytes: a change to any of these encodings, labels or derivations makes
// rosters, escrows, contributions and resharings already signed or sealed stop verifying.
describe('known answers', () => {
  const seq = (n: number, start = 0) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);
  const hexOf = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
  const sha = async (bytes: Uint8Array) => {
    await ensureSodium();

    return hexOf(sodium.crypto_hash_sha256(bytes));
  };
  const roster: RosterRecord = {
    councilId: COUNCIL,
    version: 2,
    threshold: 2,
    previousRosterHash: seq(32, 1),
    members: [3, 1, 2].map((slot) => ({ slot, userId: `user-${slot}`, identityPublicKeyWire: seq(33, slot * 10) })),
  };

  it('encodes a roster version, its hash and its fingerprint', async () => {
    expect(await sha(encodeRosterPayload(roster))).toMatchInlineSnapshot(`"f16df25f9eab1602b2db5f64396bec489000aa30efa48b2f2cd53dcfdc5bcbf7"`);
    expect(await rosterFingerprint(roster)).toMatchInlineSnapshot(`"1106067755198240921762609817914266415094"`);
    expect(await councilFingerprint({ ...roster, version: 1, previousRosterHash: new Uint8Array(0) })).toMatchInlineSnapshot(
      `"1283237802063268961152755676208279457561"`
    );
  });

  it('encodes an escrow, a contribution, a resharing and the secret commitment', async () => {
    const escrow: CouncilEscrowRecord = {
      userId: 'u',
      councilId: COUNCIL,
      rosterVersion: 2,
      rosterHash: seq(32, 2),
      threshold: 2,
      escrowCreatedAtMillis: 1_700_000_000_000,
      credentialAuthPublicKeyHash: seq(32, 3),
      secretCommitment: seq(32, 4),
      shareCommitments: seq(64, 5),
      shares: [2, 1].map((slot) => ({ slot, capsuleHash: seq(32, slot) })),
    };
    expect(await sha(encodeEscrowPayload(escrow))).toMatchInlineSnapshot(`"7a240ca71e11a8791c04c69b97b2f72c4160a24f50f1dc87b24d73884ad9ec9a"`);
    expect(
      await sha(
        encodeContributionPayload({
          requestId: 'r',
          userId: 'u',
          councilId: COUNCIL,
          slot: 2,
          custodianUserId: 'c',
          ephemeralPublicKeyHash: seq(32, 6),
          wrappedSharesHash: seq(32, 7),
          inPerson: true,
        })
      )
    ).toMatchInlineSnapshot(`"01dedf2cfff90d76fe79e68448b22d10dd48c481941ea61dc15f18eec82c0a69"`);
    expect(
      await sha(
        encodeReshareKeyBinding({
          sessionId: 's',
          councilId: COUNCIL,
          targetRosterVersion: 2,
          helperSlot: 1,
          recipientSlot: 3,
          wrappedTransferKeyHash: seq(32, 8),
        })
      )
    ).toMatchInlineSnapshot(`"daaeb32b88c80916dbdcf25f05ef0e16cc218961b39da755a3431ee24f265a59"`);
    expect(
      await sha(
        encodeReshareCommitments({
          sessionId: 's',
          councilId: COUNCIL,
          userId: 'u',
          escrowId: 'e',
          targetRosterVersion: 2,
          helperSlot: 1,
          commitments: seq(64, 9),
        })
      )
    ).toMatchInlineSnapshot(`"370c0c6b011bbb1169bca602b9da3fa14db343c505ecb470ba620d5d73f83c84"`);
    expect(hexOf(await secretCommitment('u', COUNCIL, seq(32, 10)))).toMatchInlineSnapshot(
      `"2356c48568aeceffafeab3aa162704d412f043c8e63653ea3b7ae9ecedbb84c6"`
    );
    expect(await requestFingerprint(seq(33, 11))).toMatchInlineSnapshot(`"1310385232855235409288411037596356080617"`);
    expect(
      hexOf(await deriveTransferKey(seq(32, 12), { sessionId: 's', councilId: COUNCIL, targetRosterVersion: 2, recipientSlot: 3 }))
    ).toMatchInlineSnapshot(`"9980287c5ee3b4fa6cc72f9f1a8f6238b9aa6cff45a76a44296eab79f684aafe"`);
  });

  // A fixed capsule to a seeded key pair: it opens only while the wrap, its label and its binding stay unchanged.
  it('opens a known-answer capsule, only as the share it was made for', async () => {
    await ensureSodium();
    const recipient = sodium.crypto_kem_xwing_seed_keypair(seq(32));
    const capsule = Uint8Array.from(
      Buffer.from(
        'AWAEH4ar8ZFX0TfKimiKQPaI134WbmfMTR1CtcmRdaGYRRhxFZG0UYnUr9dCIYQx/5LLSF16TOlcwxwX0Jbh1y8fXigpLuum12Kxn2E/y9gICXLMHaV7RqNHGchuWq3wbYGlt88pfwMxvV5vvY4MW1AlgR+/Pdaxr0uqLLDF7nVA+vzLjniSJ0+Ormj4hr4xpQ1GdfU43SfwvbHxfJG8Xz+yzUL3k/1CRqn9MzOQb3xw3KxQ2uTJorJdws9LTeeIidYjTIIdXCNwhChb4udHjkwq+A+PAAHvu0uFSWHcBzv76k60ZNMC0+D37fkHzE79jxPw84uC0q2K4lQ9ac5xWLAVmASc88aSQKn6daG1z0DRoqGGWRW/PutIAg/JYKaoVIbFCeX4yEu/vm1waVvaZNBN6X8A6uGfuhecclw4QeJ+LunmdAN/KqRFHJjI/sTx4WTC6gi9TYXi2AcAEp4vPdiOhAQfQIwJJa4W1lok8sRgoOjcLOQVIA1eiFH25s7NSh3Uzfnev2nD8EKb36osQ6Lu68yKYfoPjvIUEazlth6QNBx3GVf87yGievJKyZ8dXV6Iej4zD3BmNxH4dxzKVPUnt+3HivsbVy24fN82xnsMeSo4pGZCVZazALxJJmtN7Ls5GM3njYZgwadIU0DRp/Y61GkkXJROfOY6C2eBbH1ZEmlCY8gOz9H3GFJ5t83ZG/qIGofKfCznO17Pp/LOlC+Ng5k35e4q2YueOpcZuPEnGukh1Hy2GFLf7j+3NYLsM5KZs1iIe0QP2d63uwdnSBB0kmc3WNrBp+kuiQ52FILhVWRb6JjpNESyq85wBEEGIYkF4Pts8uaYJxNMTGo+UudDCwYixV0tPH5tdN+YxaLpHBzR7PCKpNi2t/YbZeIK6mEitDH3mL1tB5qNe1CUGE+3sEaT3O/Tk7JC1BH118BZYPvrrwLUh6HX0i0yBgpzAqHN9lryllsXZUQgnKXWnn48G9+oDnyfWn6Fylmrhivsz8l/LZ7Wv3WFJd9NhQ4tiz7a1E5RL102G+o+Kh3QQMouHNLUno0ity7r7DqaQFlRCt79oi0liVOLJmXOVut1sZsxVtWGcOHMrbx5LgcTELMP3yRCNK1MF6aQZXyJFCCpbFpN9nWbnR6IlL83NyxZqe6jk9lzxzqjy1sB73+W8PaBN586XRo0+NaKqY8YpCo9SXpuJbtavVI7nwo+nkJTE/6wWkvvpdD7f7ZD06WAKdOphFBPmvBw7B6s51pbiAVDm6O1oQsRuUT64X5gLho8z23K1N71Hccht1BWb9YTt7gyvvt4U/4dqXv+RyUKaDEaBrFKWR+k4N42i2P+RctjWksIzCAjZmecpHMWJbXC/xDG0Qonxero4xQMFoEad4Q8o7BWWUx32DIYlU0qRQ9W6JWjATffFC0dRzehMQUzoRFSyNB8LPUlE6XB6BwHHoFJPzvRH1hqrAoIOOlRmfhOSUXhHVPlQ1xuLMVmyuZ07YCQEAHjSZMur/laD93sXUV7Uls7QID5oCJNpiBlCln6wOHEcFosWgtVxTMPafg8DVdxrcW6iMILJQDVnTVn1uM2YAF7SZMYcsanUreZ0nc8q8T6geAkaTHPHOdWeBGt/ncqJ3VsdSK6te0bV68=',
        'base64'
      )
    );
    const binding = { userId: 'u', councilId: COUNCIL, slot: 2 };

    expect(await unwrapCapsule(capsule, [recipient.privateKey], binding)).toEqual(seq(65, 100));
    await expect(unwrapCapsule(capsule, [recipient.privateKey], { ...binding, userId: 'v' })).rejects.toThrow();
  });
});
