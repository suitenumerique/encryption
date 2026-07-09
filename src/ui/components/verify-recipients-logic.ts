// Pure decision logic for the "verify recipients" trust modal, kept free of
// React/Cunningham imports so it can be unit-tested directly.

export interface SurfacedRecipient {
  userId: string;
  /** The recipient's CURRENT identity (signature) fingerprint, from the directory. */
  fingerprint: string;
  trusted: boolean;
  /**
   * Why this recipient is blocking: 'mismatch' (a recorded fingerprint that
   * CHANGED) or 'refused' (previously refused). Carried so the UI can word the
   * warning correctly without re-deriving it.
   */
  status: 'mismatch' | 'refused';
}

/** What the vault's fetch-public-keys op returns per user (subset we read here). */
export interface VaultRegisteredUser {
  identityFingerprint: string;
  verified: boolean;
}

export interface FingerprintCheckResult {
  userId: string;
  providedFingerprint: string;
  status: 'trusted' | 'refused' | 'unknown' | 'mismatch';
}

/**
 * Build the map of userId -> identity fingerprint to run through TOFU. Only a
 * binding-verified directory record contributes a fingerprint: an unverifiable
 * record has no identity we could pin, and the wrap gate would refuse it anyway.
 */
export function buildUserFingerprints(userIds: string[], users: Record<string, VaultRegisteredUser>): Record<string, string> {
  const userFingerprints: Record<string, string> = {};

  for (const uid of userIds) {
    const entry = users[uid];

    if (entry?.verified) userFingerprints[uid] = entry.identityFingerprint;
  }

  return userFingerprints;
}

/**
 * Surface only the recipients that actually BLOCK the share: 'mismatch' (a
 * recorded fingerprint that changed) or 'refused'. 'unknown' (seen, not yet
 * verified) and 'trusted' are both allowed to proceed, so neither is surfaced:
 * first contact must not force a verification step.
 */
export function surfaceUntrustedRecipients(results: FingerprintCheckResult[]): SurfacedRecipient[] {
  return results
    .filter((r): r is FingerprintCheckResult & { status: 'mismatch' | 'refused' } => r.status === 'mismatch' || r.status === 'refused')
    .map((r) => ({ userId: r.userId, fingerprint: r.providedFingerprint, trusted: false, status: r.status }));
}

/**
 * All-or-nothing gate: the confirm ("Share") action is enabled only once every
 * surfaced recipient has been trusted. An empty list means nothing needs
 * verifying, so the share may proceed.
 */
export function allRecipientsTrusted(recipients: SurfacedRecipient[]): boolean {
  return recipients.every((r) => r.trusted);
}
