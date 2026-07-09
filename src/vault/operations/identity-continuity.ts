/**
 * Client-side TOFU continuity: when a contact presents a NEW identity, decide
 * whether it continues an identity this device already trusted, so a legitimate
 * rotation carries the old trust status forward without a fresh out-of-band
 * check. Resolved inside the normal `checkFingerprints` flow, not as a separate
 * call: on a mismatch, if the caller supplied the continuity chain (walked from
 * the directory), the check below runs.
 *
 * The chain is walked from the CURRENT identity back toward the pinned one. Each
 * link carries an identity, its previous identity's key, and a continuity
 * signature made by that previous key over this identity. The walk:
 *   1. checks each link is contiguous (its previous is the next link's identity),
 *   2. verifies each link's continuity signature, and
 *   3. stops as soon as a link's previous is the identity we pinned.
 *
 * Forging a link requires the previous identity's private key, which never
 * touches the server, so a compromised registry can only withhold links
 * (fail-safe: the change stays unknown), never fabricate trust. A hop cap bounds
 * the walk so a hostile server cannot make it run unbounded, and the status
 * propagates as-is so a refused contact cannot launder a rotation into trust.
 */
import { base64ToUint8 } from '@encryption/src/crypto/encryption-backup';
import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import { verifyIdentityContinuity } from '@encryption/src/crypto/key-registration';
import { MAX_CONTINUITY_HOPS } from '@encryption/src/shared/constants';

// Re-exported here so continuity callers can keep importing it from this module.
export { MAX_CONTINUITY_HOPS };

/** One link: an identity, the key that endorsed it, and that endorsement. */
export interface ContinuityLink {
  signaturePublicKey: string; // this identity's key (base64 wire blob)
  previousSignaturePublicKey: string; // the key that endorsed it (base64 wire blob)
  generation: number;
  algo: string;
  continuitySignature: string; // base64, sign(previous, this identity)
}

export interface ContinuityOutcome {
  chained: boolean;
  newFingerprint?: string;
}

/**
 * Walk `chain` (current identity first, back toward the pinned one) and decide
 * whether it legitimately reaches the pinned identity within the hop cap. Pure:
 * reads no state and writes none. Returns the current identity's fingerprint to
 * re-pin when the chain holds.
 *
 * KNOWN LIMITATION (downgrade), tracked as a follow-up for when identity rotation
 * is actually wired (it is not yet; every identity is generation 1 today, so the
 * checks below would be inert). A continuity link is legitimate forever and cannot
 * be revoked here. If a contact rotated gen2 -> gen3 BECAUSE gen2 leaked, a hostile
 * directory can present gen2 (with the still-valid gen1 -> gen2 link) to a device
 * pinned at gen1 and this walk will carry trust forward onto the compromised gen2.
 *
 * The full guard is two rules, both needing the identity `generation` to be pinned
 * on the TOFU entry (threaded from the directory fetch), and recorded on EVERY
 * sight so there is no baseline gap:
 *   1. DOWNGRADE: refuse carrying trust to a generation <= the highest ever seen as
 *      this contact's CURRENT identity (a rotation only ever moves forward). This
 *      is scoped to the current-identity decision, NOT to validating historical
 *      artifacts still signed by an older generation, which stay verifiable via the
 *      chain, so a slow re-sign after a rotation is unaffected.
 *   2. SAME KEY, DIFFERENT GENERATION: a fingerprint is a hash of the identity key,
 *      so one key has exactly one true generation. If the directory ever presents a
 *      pinned fingerprint with a DIFFERENT generation, that is an integrity anomaly
 *      (buggy or hostile directory), not a rotation, and must be flagged, not
 *      trusted. This half is meaningful even at gen 1.
 * Deliberately NOT bolted on as a half-tracked field here: a partial version (e.g.
 * recording generation only during continuity, not first sight) gives false
 * assurance. It belongs with the rotation flow so accept/refuse also record the
 * generation coherently. See project_identity_reconciliation.
 */
export async function resolveContinuity(remoteUserId: string, pinnedFingerprint: string, chain: ContinuityLink[]): Promise<ContinuityOutcome> {
  if (chain.length === 0 || chain.length > MAX_CONTINUITY_HOPS) return { chained: false };

  for (let i = 0; i < chain.length; i++) {
    const link = chain[i];

    // Contiguity: each link's stated previous must be the next link's identity.
    if (i + 1 < chain.length && link.previousSignaturePublicKey !== chain[i + 1].signaturePublicKey) return { chained: false };

    // Each identity must be endorsed by its stated previous.
    const endorsed = await verifyIdentityContinuity(
      {
        userId: remoteUserId,
        generation: link.generation,
        algo: link.algo,
        signaturePublicKeyWire: base64ToUint8(link.signaturePublicKey),
      },
      link.previousSignaturePublicKey,
      link.continuitySignature
    );
    if (!endorsed) return { chained: false };

    // Stop as soon as this link's previous is the identity we pinned.
    if ((await computeKeyFingerprint(link.previousSignaturePublicKey)) === pinnedFingerprint) {
      return { chained: true, newFingerprint: await computeKeyFingerprint(chain[0].signaturePublicKey) };
    }
  }

  // Walked the whole provided chain without reaching the pinned identity.
  return { chained: false };
}
