/**
 * The recovery council protocol as the vault runs it (shamir.md §5-11), kept free
 * of storage and network so it can be tested end to end: building a user's
 * escrow, a custodian's contribution, a helper's resharing, and the locked-out
 * browser's reconstruction.
 *
 * Every step that takes keys from the server checks them against something the
 * caller already trusts: the custodians' encryption keys against the identities
 * of a roster chain the caller verified, a user's escrow against that user's
 * identity, a resharing sub-share against its helper's signed transfer key, and
 * every share against Pedersen commitments whose constant term is the one the
 * user signed.
 */
import sodium from 'libsodium-wrappers-sumo';

import {
  type CouncilEscrowRecord,
  type RosterRecord,
  type SignedRosterVersion,
  capsuleHash,
  createTransferKey,
  ephemeralKeyHash,
  openSubShare,
  openTransferKey,
  rosterHash,
  sealSubShare,
  secretCommitment,
  signContribution,
  signEscrow,
  signReshareCommitments,
  signReshareKeyBinding,
  unwrapCapsule,
  unwrapRequestShare,
  verifyContribution,
  verifyEscrow,
  verifyReshareCommitments,
  verifyReshareKeyBinding,
  wrapShareForCustodian,
  wrapShareForRequest,
  wrappedSharesHash,
} from '@encryption/src/crypto/council';
import { type HybridPublicKey, type HybridSecretKey, ensureSodium } from '@encryption/src/crypto/encryption';
import { base64ToUint8, importPublicKeyFromBytes, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import {
  type Commitments,
  type ShamirShare,
  combineShares,
  decodeCommitments,
  decodeShare,
  encodeCommitments,
  encodeShare,
  equalPoints,
  reshareContribution,
  splitSecret,
  sumCommitments,
  sumSubShares,
  verifyShare,
  wipeShare,
} from '@encryption/src/crypto/shamir';
import type { SignatureSecretKey } from '@encryption/src/crypto/signature';
import type {
  CouncilCapsuleWire,
  CouncilContributionBody,
  CouncilEscrowBody,
  CouncilEscrowRecordWire,
  CouncilReleasedShares,
  CouncilReshareKeysBody,
  CouncilReshareSubSharesBody,
  RosterVersionWire,
} from '@encryption/src/shared/schemas/recovery-council';
import type { VaultKeyringWire } from '@encryption/src/shared/schemas/vault';

export function rosterRecordFromWire(councilId: string, wire: RosterVersionWire): RosterRecord {
  return {
    councilId,
    version: wire.version,
    threshold: wire.threshold,
    previousRosterHash: base64ToUint8(wire.previous_roster_hash),
    members: wire.members.map((m) => ({ slot: m.slot, userId: m.user_id, identityPublicKeyWire: base64ToUint8(m.identity_public_key) })),
  };
}

export function signedVersionFromWire(councilId: string, wire: RosterVersionWire): SignedRosterVersion {
  return {
    record: rosterRecordFromWire(councilId, wire),
    signatures: wire.signatures.map((s) => ({ identityPublicKeyWire: base64ToUint8(s.identity_public_key), signature: base64ToUint8(s.signature) })),
  };
}

export function escrowRecordFromWire(userId: string, wire: CouncilEscrowRecordWire): CouncilEscrowRecord {
  return {
    userId,
    councilId: wire.council_id,
    rosterVersion: wire.roster_version,
    rosterHash: base64ToUint8(wire.roster_hash),
    threshold: wire.threshold,
    escrowCreatedAtMillis: wire.escrow_created_at_millis,
    credentialAuthPublicKeyHash: base64ToUint8(wire.credential_auth_public_key_hash),
    secretCommitment: base64ToUint8(wire.secret_commitment),
    shareCommitments: base64ToUint8(wire.share_commitments),
    shares: wire.shares.map((s) => ({ slot: s.slot, capsuleHash: base64ToUint8(s.capsule_hash) })),
  };
}

// ----- Escrow (the user's vault) ---------------------------------------------

export interface EscrowInput {
  userId: string;
  head: RosterRecord;
  /** Each custodian's encryption key, already checked against their pinned identity. */
  custodianKeys: Map<number, HybridPublicKey>;
  /** A canonical ristretto255 scalar (randomScalar): the entropy of the dormant emergency phrase. */
  secret: Uint8Array;
  /** The dormant credential that phrase derives. */
  credential: VaultKeyringWire;
  identitySecretKey: SignatureSecretKey;
  createdAtMillis: number;
}

/** Split the secret over the head's custodians and sign what was split. */
export async function buildCouncilEscrow(input: EscrowInput): Promise<CouncilEscrowBody> {
  await ensureSodium();

  const { head } = input;
  const slots = head.members.map((m) => m.slot);
  const { shares, commitments } = splitSecret(input.secret, slots, head.threshold);
  const shareCommitments = encodeCommitments(commitments);

  const entries = await Promise.all(
    shares.map(async (share) => {
      const encoded = encodeShare(share);
      const key = input.custodianKeys.get(share.x);
      if (!key) throw new Error(`No verified encryption key for council slot ${share.x}`);

      const wrapped = await wrapShareForCustodian(encoded, key);
      encoded.fill(0);

      return { slot: share.x, wrapped };
    })
  );
  shares.forEach(wipeShare);

  const record: CouncilEscrowRecord = {
    userId: input.userId,
    councilId: head.councilId,
    rosterVersion: head.version,
    rosterHash: await rosterHash(head),
    threshold: head.threshold,
    escrowCreatedAtMillis: input.createdAtMillis,
    credentialAuthPublicKeyHash: sodium.crypto_hash_sha256(base64ToUint8(input.credential.auth_public_key)),
    secretCommitment: await secretCommitment(input.userId, head.councilId, input.secret),
    shareCommitments,
    shares: await Promise.all(entries.map(async (e) => ({ slot: e.slot, capsuleHash: await capsuleHash(e.wrapped) }))),
  };

  return {
    council_id: head.councilId,
    roster_version: head.version,
    threshold: head.threshold,
    credential: input.credential,
    escrow_created_at_millis: input.createdAtMillis,
    secret_commitment: uint8ToBase64(record.secretCommitment),
    share_commitments: uint8ToBase64(shareCommitments),
    shares: entries.map((e) => ({ slot: e.slot, wrapped_share: uint8ToBase64(e.wrapped) })),
    escrow_signature: uint8ToBase64(await signEscrow(record, input.identitySecretKey)),
  };
}

// ----- A custodian's share ------------------------------------------------------

export interface CapsuleContext {
  userId: string;
  councilId: string;
  /** The custodian's encryption secret keys, newest first. */
  secretKeys: HybridSecretKey[];
}

/**
 * The custodian's share of an escrow's current split, verified before use. A
 * direct capsule must lie on the commitments the user signed. A reshared one is
 * the sum of sub-shares, each opened under a transfer key its helper signed and
 * checked against the commitments that helper signed, whose constant terms must
 * add up to the user-signed one: whatever the server says about the helpers,
 * nothing else verifies without knowing the user's split.
 */
export async function openCustodianShare(capsule: CouncilCapsuleWire, escrow: CouncilEscrowRecord, context: CapsuleContext): Promise<Uint8Array> {
  const signed = decodeCommitments(escrow.shareCommitments);

  if (capsule.kind === 'direct') {
    const encoded = await unwrapCapsule(base64ToUint8(capsule.wrapped_share), context.secretKeys);
    const share = decodeShare(encoded);
    if (share.x !== capsule.slot) throw new Error('The capsule holds the share of another slot');
    if (!verifyShare(share, signed)) throw new Error('The share does not match the commitments the user signed');
    wipeShare(share);

    return encoded;
  }

  const subShares: ShamirShare[] = [];
  const perHelper: Commitments[] = [];

  try {
    for (const helper of capsule.helpers) {
      const helperKey = base64ToUint8(helper.helper_identity_public_key);
      const wrapped = base64ToUint8(helper.wrapped_transfer_key);
      const bound = await verifyReshareKeyBinding(
        {
          sessionId: capsule.session_id,
          councilId: context.councilId,
          targetRosterVersion: capsule.target_roster_version,
          helperSlot: helper.helper_slot,
          recipientSlot: capsule.slot,
          wrappedTransferKeyHash: sodium.crypto_hash_sha256(wrapped),
        },
        base64ToUint8(helper.binding_signature),
        helperKey
      );
      if (!bound) throw new Error(`The transfer key of helper slot ${helper.helper_slot} is not signed by that helper`);

      const commitmentBytes = base64ToUint8(helper.commitments);
      const committed = await verifyReshareCommitments(
        {
          sessionId: capsule.session_id,
          councilId: context.councilId,
          escrowId: capsule.escrow_id,
          targetRosterVersion: capsule.target_roster_version,
          helperSlot: helper.helper_slot,
          commitments: commitmentBytes,
        },
        base64ToUint8(helper.commitments_signature),
        helperKey
      );
      if (!committed) throw new Error(`The commitments of helper slot ${helper.helper_slot} are not signed by that helper`);
      const commitments = decodeCommitments(commitmentBytes);

      const transferKey = await openTransferKey(wrapped, context.secretKeys);
      const opened = await openSubShare(transferKey, base64ToUint8(helper.sealed_sub_share), {
        sessionId: capsule.session_id,
        escrowId: capsule.escrow_id,
        helperSlot: helper.helper_slot,
        recipientSlot: capsule.slot,
      }).catch(() => {
        throw new Error('A sub-share does not open for this escrow');
      });
      const subShare = decodeShare(opened);
      opened.fill(0);

      if (subShare.x !== capsule.slot || !verifyShare(subShare, commitments))
        throw new Error(`The sub-share of helper slot ${helper.helper_slot} does not match the commitments it signed`);

      subShares.push(subShare);
      perHelper.push(commitments);
    }

    if (perHelper.length === 0 || !equalPoints(sumCommitments(perHelper)[0], signed[0]))
      throw new Error('The resharing does not carry the secret the user split');

    const share = sumSubShares(capsule.slot, subShares);
    const encoded = encodeShare(share);
    wipeShare(share);

    return encoded;
  } finally {
    subShares.forEach(wipeShare);
  }
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

export interface ContributionInput {
  requestId: string;
  userId: string;
  councilId: string;
  slot: number;
  custodianUserId: string;
  ephemeralPublicKey: Uint8Array;
  encodedShare: Uint8Array;
  inPerson: boolean;
  identitySecretKey: SignatureSecretKey;
}

/** Hand one share to a recovery: wrapped for the request's ephemeral key, signed. */
export async function buildContribution(input: ContributionInput): Promise<CouncilContributionBody> {
  const wrapped = await wrapShareForRequest(input.encodedShare, importPublicKeyFromBytes(input.ephemeralPublicKey));
  const signature = await signContribution(
    {
      requestId: input.requestId,
      userId: input.userId,
      councilId: input.councilId,
      slot: input.slot,
      custodianUserId: input.custodianUserId,
      ephemeralPublicKeyHash: await ephemeralKeyHash(input.ephemeralPublicKey),
      wrappedSharesHash: await wrappedSharesHash([wrapped]),
      inPerson: input.inPerson,
    },
    input.identitySecretKey
  );

  return { slot: input.slot, wrapped_share: uint8ToBase64(wrapped), in_person: input.inPerson, signature: uint8ToBase64(signature) };
}

// ----- Reconstruction (the locked-out browser) ---------------------------------

export interface RecoveredSecret {
  secret: Uint8Array;
  /** Custodians whose signed contribution was used, with how they handed it over. */
  contributors: Array<{ slot: number; name: string | null; inPerson: boolean }>;
}

/**
 * Rebuild the emergency secret from released shares. The escrow record must
 * verify against the user's own identity; each contribution against its
 * custodian's, and each share against the current commitments, whose constant
 * term must be the one the user signed. The first `threshold` valid shares are
 * combined, and the result checked against the user-signed hash.
 */
export async function recoverCouncilSecret(
  released: CouncilReleasedShares,
  ephemeral: { publicKey: Uint8Array; secretKey: HybridSecretKey },
  userIdentityPublicKeyWire: Uint8Array
): Promise<RecoveredSecret> {
  const record = escrowRecordFromWire(released.user_id, released.escrow);
  if (!(await verifyEscrow(record, base64ToUint8(released.escrow.escrow_signature), userIdentityPublicKeyWire)))
    throw new Error('The council escrow is not signed by this user');

  const signed = decodeCommitments(record.shareCommitments);
  const current = decodeCommitments(base64ToUint8(released.share_commitments));
  if (current.length !== released.threshold || !equalPoints(current[0], signed[0]))
    throw new Error('The current split does not carry the secret the user split');

  const ephemeralHash = await ephemeralKeyHash(ephemeral.publicKey);
  const shares: Array<{ share: ShamirShare; slot: number; name: string | null; inPerson: boolean }> = [];

  for (const c of released.contributions) {
    const wrapped = base64ToUint8(c.wrapped_share);
    const authentic = await verifyContribution(
      {
        requestId: released.request_id,
        userId: released.user_id,
        councilId: released.council_id,
        slot: c.slot,
        custodianUserId: c.custodian_user_id,
        ephemeralPublicKeyHash: ephemeralHash,
        wrappedSharesHash: await wrappedSharesHash([wrapped]),
        inPerson: c.in_person,
      },
      base64ToUint8(c.signature),
      base64ToUint8(c.custodian_identity_public_key)
    );
    if (!authentic) continue;

    let share: ShamirShare;
    try {
      const encoded = await unwrapRequestShare(wrapped, ephemeral.secretKey);
      share = decodeShare(encoded);
      encoded.fill(0);
    } catch {
      continue;
    }

    if (share.x !== c.slot || !verifyShare(share, current)) {
      wipeShare(share);
      continue;
    }

    shares.push({ share, slot: c.slot, name: c.custodian_name, inPerson: c.in_person });
  }

  try {
    if (shares.length < released.threshold) throw new Error('Not enough valid shares to rebuild the secret');

    const used = shares.slice(0, released.threshold);
    const secret = combineShares(used.map((s) => s.share));
    if (!equal(await secretCommitment(released.user_id, released.council_id, secret), record.secretCommitment)) {
      secret.fill(0);
      throw new Error('The shares do not give the committed secret');
    }

    return { secret, contributors: used.map((s) => ({ slot: s.slot, name: s.name, inPerson: s.inPerson })) };
  } finally {
    for (const s of shares) wipeShare(s.share);
  }
}

// ----- Resharing (a helper's vault) ---------------------------------------------

export interface ReshareTarget {
  sessionId: string;
  councilId: string;
  target: RosterRecord;
  helperSlots: number[];
  mySlot: number;
  /** The target custodians' encryption keys, checked against the target's identities. */
  recipientKeys: Map<number, HybridPublicKey>;
  identitySecretKey: SignatureSecretKey;
}

/** One transfer key per target custodian, signed; the keys stay with the helper for the session. */
export async function buildReshareKeys(input: ReshareTarget): Promise<{ body: CouncilReshareKeysBody; transferKeys: Map<number, Uint8Array> }> {
  const transferKeys = new Map<number, Uint8Array>();
  const keys = [];

  for (const member of input.target.members) {
    const recipientKey = input.recipientKeys.get(member.slot);
    if (!recipientKey) throw new Error(`No verified encryption key for council slot ${member.slot}`);

    const { transferKey, wrapped } = await createTransferKey(recipientKey);
    transferKeys.set(member.slot, transferKey);

    const signature = await signReshareKeyBinding(
      {
        sessionId: input.sessionId,
        councilId: input.councilId,
        targetRosterVersion: input.target.version,
        helperSlot: input.mySlot,
        recipientSlot: member.slot,
        wrappedTransferKeyHash: sodium.crypto_hash_sha256(wrapped),
      },
      input.identitySecretKey
    );

    keys.push({ recipient_slot: member.slot, wrapped_transfer_key: uint8ToBase64(wrapped), binding_signature: uint8ToBase64(signature) });
  }

  return { body: { keys }, transferKeys };
}

/** The helper's sub-shares of one escrow, each sealed for its target custodian, and the commitments it signs for them. */
export async function buildReshareSubShares(
  input: Pick<ReshareTarget, 'sessionId' | 'councilId' | 'target' | 'helperSlots' | 'mySlot' | 'identitySecretKey'>,
  transferKeys: Map<number, Uint8Array>,
  escrowId: string,
  encodedShare: Uint8Array
): Promise<CouncilReshareSubSharesBody['escrows'][number]> {
  const share = decodeShare(encodedShare);
  if (share.x !== input.mySlot) throw new Error('The share is not the helper’s own');

  const targetSlots = input.target.members.map((m) => m.slot);
  const { subShares, commitments } = reshareContribution(share, input.helperSlots, targetSlots, input.target.threshold);
  wipeShare(share);

  const commitmentBytes = encodeCommitments(commitments);
  const signature = await signReshareCommitments(
    {
      sessionId: input.sessionId,
      councilId: input.councilId,
      escrowId,
      targetRosterVersion: input.target.version,
      helperSlot: input.mySlot,
      commitments: commitmentBytes,
    },
    input.identitySecretKey
  );

  const sealed = [];
  try {
    for (const subShare of subShares) {
      const encoded = encodeShare(subShare);
      sealed.push({
        recipient_slot: subShare.x,
        sealed: uint8ToBase64(
          await sealSubShare(transferKeys.get(subShare.x)!, encoded, {
            sessionId: input.sessionId,
            escrowId,
            helperSlot: input.mySlot,
            recipientSlot: subShare.x,
          })
        ),
      });
      encoded.fill(0);
    }
  } finally {
    subShares.forEach(wipeShare);
  }

  return {
    escrow_id: escrowId,
    commitments: uint8ToBase64(commitmentBytes),
    commitments_signature: uint8ToBase64(signature),
    sub_shares: sealed,
  };
}
