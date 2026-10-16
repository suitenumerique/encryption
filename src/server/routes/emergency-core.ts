import { type EmergencyEscrowRecord, sha256, verifyEmergencyEscrow } from '@encryption/src/crypto/emergency-escrow';
import { base64ToUint8, importPublicKeyFromBytes } from '@encryption/src/crypto/encryption-backup';
import { verifyAuthPublicKeyBinding } from '@encryption/src/crypto/vault-unlock';
import type { EmergencyAccessStatus } from '@encryption/src/generated/prisma/client';
import { prisma } from '@encryption/src/prisma/client';
import { sendEmergencyVaultRecovered, sendEmergencyVaultRecoveredContact } from '@encryption/src/server/email/emergency';
import type { EmergencyEscrowFieldsWire } from '@encryption/src/shared/schemas/emergency-access';
import type { VaultKeyringWire } from '@encryption/src/shared/schemas/vault';

export const HOUR_MS = 60 * 60 * 1000;
export const DAY_MS = 24 * HOUR_MS;

// User-chosen opposition window bounds (days). The UI offers 7/15/30 presets
// plus a custom value; the server accepts the full range.
export const WAIT_TIME_MIN_DAYS = 1;
export const WAIT_TIME_MAX_DAYS = 90;

export type EmergencyApprovalFields = {
  status: EmergencyAccessStatus;
  recoveryRequestedAt: Date | null;
  waitTimeDays: number;
};

// Whether a trusted contact's recovery is granted RIGHT NOW. This arithmetic is
// the single authority on the wait period: every release point (capsule release,
// emergency-credential unlock candidacy) calls it directly instead of trusting
// the stored status, so a stalled notification job can never shorten or lengthen
// the wait. The hourly job flips the status column and sends the emails; this
// predicate is what actually opens the gate.
export function emergencyApprovalHolds(ea: EmergencyApprovalFields, nowMs: number): boolean {
  if (ea.status === 'recoveryApproved') return true;
  if (ea.status !== 'recoveryRequested' || ea.recoveryRequestedAt === null) return false;

  return ea.recoveryRequestedAt.getTime() + ea.waitTimeDays * DAY_MS <= nowMs;
}

export function emergencyDeadlineMillis(ea: Pick<EmergencyApprovalFields, 'recoveryRequestedAt' | 'waitTimeDays'>): number | null {
  return ea.recoveryRequestedAt === null ? null : ea.recoveryRequestedAt.getTime() + ea.waitTimeDays * DAY_MS;
}

export interface EscrowSubmission {
  grantorUserId: string;
  granteeUserId: string;
  waitTimeDays: number;
  credential: VaultKeyringWire;
  escrow: EmergencyEscrowFieldsWire;
}

/**
 * Fail-safe check of a submitted escrow (designation, re-arm, or the burn +
 * re-arm carried by a phrase change) against the grantor's ACTIVE identity key:
 * the emergency credential's auth verifier must be identity-bound exactly like
 * a keyring write, and the binding signature must cover every escrow parameter
 * (including the hashes of that verifier and of the capsule, so none of them
 * can be swapped after signing). Malformed input returns false, never throws.
 */
export async function verifyEscrowSubmission(submission: EscrowSubmission, grantorIdentityKeyBytes: Uint8Array): Promise<boolean> {
  try {
    const identityRawKey = importPublicKeyFromBytes(grantorIdentityKeyBytes);
    const authPublicKey = base64ToUint8(submission.credential.auth_public_key);

    const authBound = await verifyAuthPublicKeyBinding(authPublicKey, base64ToUint8(submission.credential.auth_pub_sig), identityRawKey);
    if (!authBound) return false;

    const record: EmergencyEscrowRecord = {
      grantorUserId: submission.grantorUserId,
      granteeUserId: submission.granteeUserId,
      granteeIdentityPublicKeyWire: base64ToUint8(submission.escrow.grantee_identity_public_key),
      waitTimeDays: submission.waitTimeDays,
      escrowCreatedAtMillis: submission.escrow.escrow_created_at_millis,
      credentialAuthPublicKeyHash: await sha256(authPublicKey),
      capsuleHash: await sha256(base64ToUint8(submission.escrow.wrapped_phrase_for_grantee)),
    };

    return await verifyEmergencyEscrow(record, base64ToUint8(submission.escrow.escrow_signature), identityRawKey);
  } catch {
    return false;
  }
}

/**
 * Where and in which language to email a user: the address and language stored
 * on the user record, both refreshed from the OIDC claims on each login.
 */
export async function emergencyRecipient(userId: string): Promise<{ email: string; locale: string } | null> {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return null;

  return { email: user.email, locale: user.language === 'fr' ? 'fr' : 'en' };
}

/**
 * Post-recovery notifications (burn + re-arm committed): both sides learn the
 * phrase handover is closed. The grantor gets ONE mail naming every contact
 * involved, not one per contact.
 */
export async function notifyVaultRecovered(grantorUserId: string, granteeUserIds: string[]): Promise<void> {
  const [grantor, grantees] = await Promise.all([
    emergencyRecipient(grantorUserId),
    Promise.all(granteeUserIds.map((granteeUserId) => emergencyRecipient(granteeUserId))),
  ]);
  if (!grantor) return;

  const reachable = grantees.filter((grantee) => grantee !== null);

  await Promise.all([
    sendEmergencyVaultRecovered({ recipient: grantor.email, locale: grantor.locale, granteeEmail: reachable.map((g) => g.email).join(', ') }),
    ...reachable.map((grantee) =>
      sendEmergencyVaultRecoveredContact({ recipient: grantee.email, locale: grantee.locale, grantorEmail: grantor.email })
    ),
  ]);
}
