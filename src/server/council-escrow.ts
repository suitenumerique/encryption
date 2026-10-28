/**
 * Escrow submissions (enrollment, re-enrollment, re-arm after a recovery): the
 * checks against the head of the council and the write, shared by the council
 * routes and the phrase change (`PUT /api/vault/keyring`).
 */
import { type CouncilEscrowRecord, capsuleHash, rosterHash, verifyEscrow } from '@encryption/src/crypto/council';
import { ensureSodium } from '@encryption/src/crypto/encryption';
import { base64ToUint8, importPublicKeyFromBytes, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { decodeCommitments } from '@encryption/src/crypto/shamir';
import { verifyAuthPublicKeyBinding } from '@encryption/src/crypto/vault-unlock';
import type { Prisma } from '@encryption/src/generated/prisma/client';
import { prisma } from '@encryption/src/prisma/client';
import {
  type RosterVersionRow,
  type SignedShareEntry,
  configuredCouncils,
  councilHead,
  rosterRecordOf,
  sha256,
} from '@encryption/src/server/council-core';
import { councilForEmail } from '@encryption/src/server/recovery-councils';
import { kdfParamsAllowed } from '@encryption/src/server/routes/kdf-params';
import { activeIdentityWireKey } from '@encryption/src/server/routes/transport-auth';
import {
  API_ERROR_COUNCIL_ESCROW_INVALID,
  API_ERROR_COUNCIL_NOT_FOUND,
  API_ERROR_COUNCIL_ROSTER_CHANGED,
  API_ERROR_VAULT_KDF_PARAMS_INVALID,
  API_ERROR_VAULT_NOT_FOUND,
} from '@encryption/src/shared/error-codes';
import type { CouncilEscrowBody } from '@encryption/src/shared/schemas/recovery-council';

/**
 * The council a user may enroll with: the one their escrow already names (an
 * email change does not move it), else the one covering their email.
 */
export async function enrollableCouncil(userId: string): Promise<string | null> {
  const escrow = await prisma.councilEscrow.findFirst({ where: { userId }, orderBy: { createdAt: 'desc' }, select: { councilId: true } });
  if (escrow) return escrow.councilId;

  const user = await prisma.user.findUnique({ where: { id: userId }, select: { email: true } });

  return user ? (councilForEmail(configuredCouncils(), user.email)?.id ?? null) : null;
}

export type EscrowCheck =
  | { ok: true; head: RosterVersionRow; identityKey: Uint8Array; record: CouncilEscrowRecord }
  | { ok: false; status: 400 | 404 | 409; code: string };

/**
 * Check a submitted escrow against the head of its council: one capsule per
 * custodian of the head, its threshold, the credential's auth verifier bound to
 * the user's identity, and the identity signature over the whole record.
 */
export async function checkEscrowSubmission(userId: string, body: CouncilEscrowBody): Promise<EscrowCheck> {
  const head = await councilHead(body.council_id);
  if (!head) return { ok: false, status: 404, code: API_ERROR_COUNCIL_NOT_FOUND };
  if (head.version !== body.roster_version || head.threshold !== body.threshold)
    return { ok: false, status: 409, code: API_ERROR_COUNCIL_ROSTER_CHANGED };

  const headSlots = head.members.map((m) => m.slot).sort((a, b) => a - b);
  const sentSlots = body.shares.map((s) => s.slot).sort((a, b) => a - b);
  if (sentSlots.length !== headSlots.length || sentSlots.some((slot, i) => slot !== headSlots[i]))
    return { ok: false, status: 409, code: API_ERROR_COUNCIL_ROSTER_CHANGED };

  if (!kdfParamsAllowed(body.credential.kdf_ops, body.credential.kdf_mem))
    return { ok: false, status: 400, code: API_ERROR_VAULT_KDF_PARAMS_INVALID };

  const identityKey = await activeIdentityWireKey(userId);
  if (!identityKey) return { ok: false, status: 404, code: API_ERROR_VAULT_NOT_FOUND };

  try {
    const authPublicKey = base64ToUint8(body.credential.auth_public_key);
    if (!(await verifyAuthPublicKeyBinding(authPublicKey, base64ToUint8(body.credential.auth_pub_sig), importPublicKeyFromBytes(identityKey))))
      return { ok: false, status: 400, code: API_ERROR_COUNCIL_ESCROW_INVALID };

    await ensureSodium();
    const shareCommitments = base64ToUint8(body.share_commitments);
    if (decodeCommitments(shareCommitments).length !== body.threshold) return { ok: false, status: 400, code: API_ERROR_COUNCIL_ESCROW_INVALID };

    const record: CouncilEscrowRecord = {
      userId,
      councilId: body.council_id,
      rosterVersion: head.version,
      rosterHash: await rosterHash(rosterRecordOf(head)),
      threshold: body.threshold,
      escrowCreatedAtMillis: body.escrow_created_at_millis,
      credentialAuthPublicKeyHash: sha256(authPublicKey),
      secretCommitment: base64ToUint8(body.secret_commitment),
      shareCommitments,
      shares: await Promise.all(body.shares.map(async (s) => ({ slot: s.slot, capsuleHash: await capsuleHash(base64ToUint8(s.wrapped_share)) }))),
    };

    if (!(await verifyEscrow(record, base64ToUint8(body.escrow_signature), identityKey)))
      return { ok: false, status: 400, code: API_ERROR_COUNCIL_ESCROW_INVALID };

    return { ok: true, head, identityKey, record };
  } catch {
    return { ok: false, status: 400, code: API_ERROR_COUNCIL_ESCROW_INVALID };
  }
}

/** The head changed between the check and the write: the vault must split again (409). */
export class CouncilHeadChangedError extends Error {
  constructor() {
    super('The council head changed since the escrow was checked');
    this.name = 'CouncilHeadChangedError';
  }
}

/**
 * Write a checked escrow: its dormant credential, the escrow row and one capsule
 * per custodian. Returns the escrow id; throws CouncilHeadChangedError when the
 * head changed since the check.
 */
export async function writeEscrow(
  tx: Prisma.TransactionClient,
  userId: string,
  vaultId: string,
  body: CouncilEscrowBody,
  checked: Extract<EscrowCheck, { ok: true }>
): Promise<string> {
  if ((await councilHead(body.council_id, tx))?.id !== checked.head.id) throw new CouncilHeadChangedError();

  const credential = await tx.vaultCredential.create({
    data: {
      vaultId,
      type: 'council',
      wrappedVrk: body.credential.wrapped_vrk,
      authPublicKey: Buffer.from(base64ToUint8(body.credential.auth_public_key)),
      authPubSig: Buffer.from(base64ToUint8(body.credential.auth_pub_sig)),
      kdfOps: body.credential.kdf_ops,
      kdfMem: body.credential.kdf_mem,
      lang: body.credential.lang,
    },
  });

  const signedShares: SignedShareEntry[] = checked.record.shares.map((s) => ({ slot: s.slot, capsule_hash: uint8ToBase64(s.capsuleHash) }));

  const escrow = await tx.councilEscrow.create({
    data: {
      userId,
      councilId: body.council_id,
      credentialId: credential.id,
      rosterVersionId: checked.head.id,
      threshold: body.threshold,
      generation: 1,
      signedRosterVersionId: checked.head.id,
      signedThreshold: body.threshold,
      signedShares: signedShares as unknown as Prisma.InputJsonValue,
      signedCommitments: Buffer.from(checked.record.shareCommitments),
      commitments: Buffer.from(checked.record.shareCommitments),
      secretCommitment: Buffer.from(checked.record.secretCommitment),
      escrowSignature: Buffer.from(base64ToUint8(body.escrow_signature)),
      escrowCreatedAt: new Date(body.escrow_created_at_millis),
    },
  });

  await tx.councilCapsule.createMany({
    data: body.shares.map((s) => ({
      escrowId: escrow.id,
      generation: 1,
      slot: s.slot,
      identityId: checked.head.members.find((m) => m.slot === s.slot)!.identityId,
      wrappedShare: s.wrapped_share,
    })),
  });

  return escrow.id;
}
