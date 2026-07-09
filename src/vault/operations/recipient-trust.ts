/**
 * Wrap-time recipient trust gate.
 *
 * Before the vault wraps a symmetric key for a set of recipients, it must tie
 * the encryption key it is about to use to the identity the owner actually
 * trusts. Two independent substitutions have to be blocked:
 *
 *   1. Swap the encryption key under a real identity — blocked by the BINDING
 *      signature (Ed25519 by the identity key over the encryption key + metadata);
 *      an attacker can't forge it without the identity's secret key.
 *   2. Swap the whole identity (attacker's identity + matching binding) — blocked
 *      by TOFU: the record's identity fingerprint must equal the one the owner
 *      pinned as 'trusted' for that userId.
 *
 * Checking these separately (as a product might) is not enough: they must both
 * hold for the SAME record at the SAME moment, which is why this runs inside the
 * vault at wrap time. A directory that is a MITM cannot get the vault to wrap for
 * a key that isn't bound by the trusted identity.
 *
 * The directory fetch is batched: all recipients resolve in ONE request, and the
 * TOFU map is loaded once, so sharing to N users is not N round-trips.
 */
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { handleFetchPublicKeys } from '@encryption/src/vault/operations/fetch-public-keys';
import { handleCheckFingerprints } from '@encryption/src/vault/operations/fingerprint-registry';

/**
 * Resolve the encryption public keys (as ArrayBuffer, the shape the low-level
 * wrap ops accept) to wrap for, keyed by userId, enforcing BOTH checks the vault
 * owns so the PRODUCT never has to:
 *
 *   1. Binding — handleFetchPublicKeys runs verifyKeyRegistration on each record
 *      and withholds (null) any encryption key not provably signed by its
 *      identity key. That is the "does this encryption key belong to this
 *      identity" check, done here before anything is wrapped.
 *   2. Trust — the identity fingerprint is run through TOFU (handleCheckFingerprints):
 *      first sight RECORDS the fingerprint as 'unknown' (seen, not verified) and is
 *      allowed; a matching known fingerprint keeps its status; a CHANGED fingerprint
 *      resolves to 'mismatch' (the dangerous case) and is blocked; 'refused' is
 *      blocked. So 'trusted' and 'unknown' proceed; 'mismatch' and 'refused' do not.
 *      There is deliberately no trust-on-first-use: 'trusted' comes only from an
 *      explicit user decision.
 *
 * Because TOFU lives here, sharing does not require the product to call
 * checkFingerprints. The product surfaces fingerprints only for EXPLICIT
 * verification (a profile/contact view) and to react when this gate refuses.
 * Throws UNTRUSTED_RECIPIENT (all-or-nothing) listing the offending userIds, which
 * for this gate means a mismatch or a refusal (never a mere first encounter).
 */
export async function resolveTrustedRecipientKeys(ownerUserId: string, recipientUserIds: string[]): Promise<Record<string, ArrayBuffer>> {
  const unique = [...new Set(recipientUserIds)];

  if (unique.length === 0) return {};

  // One batched directory fetch; each entry is binding-verified in the vault.
  const { users } = await handleFetchPublicKeys(ownerUserId, { userIds: unique });

  // Run TOFU on the fingerprints of the binding-verified records (first-sight
  // pin, match, continuity carry-forward, or 'unknown' on a mismatch). currentUserId
  // makes the owner's own identity always trusted.
  const userFingerprints: Record<string, string> = {};

  for (const uid of unique) {
    const entry = users[uid];

    if (entry?.verified && entry.encryptionPublicKey) userFingerprints[uid] = entry.identityFingerprint;
  }

  // record: true — this is an ACTUAL share, so first-sight recipients are recorded
  // as 'unknown' (and self / continuity persisted). A product's read-only status
  // check does not set this, so listing people never floods the vault.
  const { results } = await handleCheckFingerprints(ownerUserId, { userFingerprints, currentUserId: ownerUserId }, { record: true });
  const statusByUser = new Map(results.map((r) => [r.userId, r.status]));

  const resolved: Record<string, ArrayBuffer> = {};
  const rejected: string[] = [];

  for (const uid of unique) {
    const entry = users[uid];
    const status = statusByUser.get(uid);

    // Cannot wrap if the binding failed / is missing. Trust-wise, only 'refused'
    // and 'mismatch' block: a contact the user refused, or one whose RECORDED
    // fingerprint has since CHANGED (the dangerous case the verify modal exists
    // for). 'unknown' (seen, not yet verified) and 'trusted' both proceed, so
    // sharing to a not-yet-verified contact is allowed; verifying is a separate,
    // explicit user action, and a mismatch is what forces a decision.
    if (!entry || !entry.verified || !entry.encryptionPublicKey || (status !== 'trusted' && status !== 'unknown')) {
      rejected.push(uid);
      continue;
    }

    resolved[uid] = entry.encryptionPublicKey;
  }

  if (rejected.length > 0) {
    throw new VaultError(VaultErrorCode.UNTRUSTED_RECIPIENT, `Refusing to wrap for untrusted or unverified recipients: ${rejected.join(', ')}`);
  }

  return resolved;
}
