/**
 * TOFU trust registry, backed by the synchronized vault's `tofu` map (so a
 * trust decision made on one device syncs to the others). Handlers keep their
 * original I/O contract; only the backing store changed from a standalone
 * IndexedDB store to VaultState. A refused or first-seen fingerprint is a
 * trusted/refused entry keyed by the remote user's id; `unknown` is never
 * persisted — it is the transient "stored trusted, but a different fingerprint
 * arrived" verdict that needs a user decision.
 */
import { computeKeyFingerprint } from '@encryption/src/crypto';
import { type TofuStatus, type VaultState, activeIdentity, setTofu } from '@encryption/src/crypto/vault-state';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { fetchContinuityChain, handleFetchPublicKeys } from '@encryption/src/vault/operations/fetch-public-keys';
import { type ContinuityLink, resolveContinuity } from '@encryption/src/vault/operations/identity-continuity';
import { handleSync } from '@encryption/src/vault/operations/vault-sync-run';
import { loadVault, mutateVault } from '@encryption/src/vault/vault-keys';

// Write-through for a TOFU decision: apply it AS PART OF a sync, so the change is
// pushed to the server (the identity-signed data-plane needs no OIDC token) and
// persisted locally ONLY if that push succeeds. A failed push throws, so the trust
// is never silently kept local (which is what left it missing after a restore /
// device transfer before this was wired). `mutateVault` remains for local-only
// state that is not synced.
async function writeThrough(userId: string, mutate: (state: VaultState) => VaultState): Promise<void> {
  const result = await handleSync(userId, { mutate });

  if (result.status !== 'ok') {
    throw new VaultError(VaultErrorCode.SYNC_FAILED, 'The change could not be saved to the server. Please try again.');
  }
}

// Result statuses returned to the caller. 'unknown' (seen, unverified) and
// 'trusted' let the wrap gate proceed; 'refused' and 'mismatch' (a recorded
// fingerprint that has since CHANGED) block it and drive the verify modal.
// Only 'unknown' | 'trusted' | 'refused' are ever PERSISTED; 'mismatch' is a
// transient verdict computed at check time.
type FingerprintStatus = 'trusted' | 'refused' | 'unknown' | 'mismatch';

export interface FingerprintCheckResult {
  userId: string;
  knownFingerprint: string | null;
  providedFingerprint: string;
  status: FingerprintStatus;
}

/**
 * Check fingerprints provided by the product against the local registry.
 *
 * - First encounter: RECORD the fingerprint as "unknown" (seen, not verified) so a
 *   later change is detectable, but do NOT mark it trusted. Sharing to an unknown
 *   contact is allowed; there is deliberately no trust-on-first-use. Trust
 *   ("trusted") comes only from an EXPLICIT user decision (accept-fingerprint).
 * - Match: status = the stored status (unknown, trusted, or refused).
 * - Mismatch with a recorded fingerprint: "mismatch" (the dangerous case, a
 *   contact's key has changed), which the wrap gate blocks and the verify modal
 *   surfaces, UNLESS the vault first fetches that contact's continuity chain from
 *   the directory and it proves the new identity chains from the recorded one, in
 *   which case the recorded status is carried forward and the new fingerprint
 *   re-recorded. The directory fetch is injectable so tests stay offline.
 *
 * The wrap gate allows "unknown" and "trusted"; it blocks "refused" and "mismatch"
 * (the two cases the verify modal exists for). When this device has no vault yet
 * (pre-onboarding or after destroy-keys), every fingerprint reads as "unknown".
 */
export async function handleCheckFingerprints(
  userId: string,
  payload: {
    /** Fingerprints keyed by INTERNAL user id (the TOFU key space). Boundary callers holding subs go through {@link handleCheckFingerprintsBySubs}. */
    userFingerprints: Record<string, string>;
  },
  // `record` controls PERSISTENCE. It is true ONLY on the wrap-time path (an
  // actual share, resolveTrustedRecipientKeys): only then do we record a
  // first-sight 'unknown' (and self / continuity carry-forward). A bare read
  // (a product listing people to show trust status) passes it false/absent and
  // writes NOTHING, so merely displaying a roster never floods the vault with an
  // 'unknown' entry per person ever looked at. The computed results are identical
  // either way; only whether they are persisted differs.
  deps: { fetchContinuityChain?: (remoteUserId: string) => Promise<ContinuityLink[]>; record?: boolean } = {}
): Promise<{ results: FingerprintCheckResult[] }> {
  const fetchChain = deps.fetchContinuityChain ?? fetchContinuityChain;
  const loaded = await loadVault(userId);

  // No vault on this device: there is no trust state to consult and nothing can be
  // shared anyway (no keys), so a product has no reason to be checking fingerprints
  // yet. Fail loudly rather than answering "unknown" for everything: it signals
  // "set up encryption first" instead of silently pretending to have checked.
  if (!loaded) {
    throw new VaultError(VaultErrorCode.NOT_INITIALIZED, 'No vault on this device; set up encryption before checking fingerprints.');
  }

  const tofu = loaded.state.tofu;

  // The operating user's OWN identity fingerprint, derived from the local vault,
  // never from the caller. A product declares `currentUserId`, but that is
  // attacker-controllable: a compromised product could pass another contact's id
  // to have an attacker fingerprint pinned as trusted for that contact. So "self"
  // is strictly the vault's authenticated session user (`userId`), and the pinned
  // value is the local identity's fingerprint, not the payload's.
  const localIdentity = activeIdentity(loaded.state);
  const selfFingerprint = localIdentity ? await computeKeyFingerprint(localIdentity.signaturePublicKey) : null;

  const results: FingerprintCheckResult[] = [];
  // Entries written: self-trust (the user's own identity), a first-sight RECORD of
  // a contact as 'unknown' (so a later change is detectable), and a continuity
  // carry-forward of an already-decided status. A mismatch never writes (it needs
  // an explicit decision); 'trusted'/'refused' come only from accept/refuse.
  const writes: Array<{
    remoteUserId: string;
    fingerprint: string;
    status: TofuStatus;
    kind: 'self' | 'first-sight' | 'continuity';
    basedOn?: string;
  }> = [];

  for (const [remoteUserId, providedFingerprint] of Object.entries(payload.userFingerprints)) {
    // A user always trusts their own identity — but only the vault's own session
    // user, and pinned to the locally-derived fingerprint (see note above).
    if (remoteUserId === userId) {
      const fp = selfFingerprint ?? providedFingerprint;
      writes.push({ remoteUserId, fingerprint: fp, status: 'trusted', kind: 'self' });
      results.push({ userId: remoteUserId, knownFingerprint: fp, providedFingerprint, status: 'trusted' });
      continue;
    }

    const known = tofu[remoteUserId];
    const active = known && !known.deleted ? known : undefined;

    if (!active) {
      // First encounter: RECORD the fingerprint as 'unknown' (seen, not verified)
      // so a later change surfaces as a mismatch, but do NOT mark it trusted.
      // Sharing to an unknown contact is allowed; trust comes only from an explicit
      // accept. No modal, no block on first contact.
      writes.push({ remoteUserId, fingerprint: providedFingerprint, status: 'unknown', kind: 'first-sight' });
      results.push({ userId: remoteUserId, knownFingerprint: null, providedFingerprint, status: 'unknown' });
      continue;
    }

    // Sticky refusal: once a contact is refused, they STAY refused no matter what
    // fingerprint is presented (matching or rotated). An attacker must not be able
    // to escape a refusal by rotating keys, and the user must not be nudged into
    // re-trusting a contact they deliberately distrusted. Only an explicit un-refuse
    // (accept-fingerprint / delete) clears it. This is checked before the mismatch
    // path so a key change never downgrades 'refused' to a neutral 'mismatch'.
    if (active.status === 'refused') {
      results.push({ userId: remoteUserId, knownFingerprint: active.fingerprint, providedFingerprint, status: 'refused' });
      continue;
    }

    if (active.fingerprint === providedFingerprint) {
      results.push({ userId: remoteUserId, knownFingerprint: active.fingerprint, providedFingerprint, status: active.status });
      continue;
    }

    // A trusted/unknown contact's recorded fingerprint has CHANGED: a mismatch. Try
    // to carry the recorded status across a legitimate rotation. Fetch the contact's continuity chain
    // from the directory and see whether it leads from the recorded identity to
    // exactly this new fingerprint. Any fetch failure is swallowed so the mismatch
    // stays fail-safe (blocked).
    let chain: ContinuityLink[] = [];

    try {
      chain = await fetchChain(remoteUserId);
    } catch {
      chain = [];
    }

    const outcome = chain.length > 0 ? await resolveContinuity(remoteUserId, active.fingerprint, chain) : { chained: false as const };

    if (outcome.chained && outcome.newFingerprint === providedFingerprint) {
      writes.push({ remoteUserId, fingerprint: providedFingerprint, status: active.status, kind: 'continuity', basedOn: active.fingerprint });
      results.push({ userId: remoteUserId, knownFingerprint: active.fingerprint, providedFingerprint, status: active.status });
    } else {
      results.push({ userId: remoteUserId, knownFingerprint: active.fingerprint, providedFingerprint, status: 'mismatch' });
    }
  }

  // Persist self-trust, first-sight records, and any continuity carry-forward.
  // Every decision above was computed from a snapshot read BEFORE the cache lock,
  // so re-check under the lock (inside mutateVault) to avoid clobbering a decision a
  // concurrent sync merged in the meantime. Skipping unchanged entries also stops a
  // repeated self/first-sight check from resealing the vault on every call, which
  // would otherwise cause perpetual cross-device sync churn.
  if (deps.record && writes.length > 0) {
    const now = Date.now();
    await mutateVault(userId, (state) =>
      writes.reduce((acc, w) => {
        const current = acc.tofu[w.remoteUserId];
        const active = current && !current.deleted ? current : undefined;

        if (w.kind === 'continuity') {
          // Carry trust forward only if the pinned identity under the lock is
          // still the one the continuity walk started from; otherwise a
          // concurrent decision has superseded ours and must stand.
          if (!active || active.fingerprint !== w.basedOn) return acc;

          return setTofu(acc, w.remoteUserId, w.fingerprint, w.status, now);
        }

        // self / first-sight: only write when there is no active entry. This never
        // overwrites an entry another writer created (a decision from another
        // device, or a first-sight record already present), and no-ops when it
        // already exists so we don't churn the vault.
        if (active) return acc;

        return setTofu(acc, w.remoteUserId, w.fingerprint, w.status, now);
      }, state)
    );
  }

  return { results };
}

/**
 * Boundary variant of {@link handleCheckFingerprints} for callers that hold
 * subs (products, the interface's verify screens): resolves each sub through
 * the directory to the internal id the TOFU store keys on, checks, and maps
 * the results back to the caller's subs. A sub with no directory record cannot
 * be checked and reads as 'unknown' with no recorded fingerprint.
 */
export async function handleCheckFingerprintsBySubs(
  userId: string,
  payload: { userFingerprints: Record<string, string> }
): Promise<{ results: FingerprintCheckResult[] }> {
  const subs = Object.keys(payload.userFingerprints);

  if (subs.length === 0) return { results: [] };

  const { users } = await handleFetchPublicKeys(userId, { subs });

  const internalFingerprints: Record<string, string> = {};

  for (const sub of subs) {
    const entry = users[sub];

    if (entry) {
      internalFingerprints[entry.userId] = payload.userFingerprints[sub];
    }
  }

  const { results } = await handleCheckFingerprints(userId, { userFingerprints: internalFingerprints });
  const byInternal = new Map(results.map((r) => [r.userId, r]));

  // One result per QUERIED sub — two subs resolving to the same internal user
  // (email-linked credentials) each get the shared verdict, and an
  // unresolvable sub reads as 'unknown' with nothing recorded.
  return {
    results: subs.map((sub) => {
      const verdict = users[sub] ? byInternal.get(users[sub].userId) : undefined;

      return verdict
        ? { ...verdict, userId: sub, providedFingerprint: payload.userFingerprints[sub] }
        : { userId: sub, knownFingerprint: null, providedFingerprint: payload.userFingerprints[sub], status: 'unknown' as const };
    }),
  };
}

/** Accept a fingerprint: mark it trusted in the synchronized registry (write-through). Keys by INTERNAL id. */
export async function handleAcceptFingerprint(userId: string, payload: { userId: string; fingerprint: string }): Promise<void> {
  await writeThrough(userId, (state) => setTofu(state, payload.userId, payload.fingerprint, 'trusted', Date.now()));
}

/** Refuse a fingerprint: mark it refused so the UI shows it in red (write-through). Keys by INTERNAL id. */
export async function handleRefuseFingerprint(userId: string, payload: { userId: string; fingerprint: string }): Promise<void> {
  await writeThrough(userId, (state) => setTofu(state, payload.userId, payload.fingerprint, 'refused', Date.now()));
}

// Resolve one sub to the internal id a trust decision must be recorded under.
// Trust decisions are meaningless without a directory record (the fingerprint
// being decided on comes from one), so an unresolvable sub is an error.
async function resolveDecisionTarget(userId: string, sub: string): Promise<string> {
  const { users } = await handleFetchPublicKeys(userId, { subs: [sub] });
  const entry = users[sub];

  if (!entry) {
    throw new VaultError(VaultErrorCode.UNRESOLVED_USER, 'This person has no registered encryption identity to decide on.');
  }

  return entry.userId;
}

/** Boundary variant of {@link handleAcceptFingerprint} for callers holding a sub (the verify/profile screens). */
export async function handleAcceptFingerprintBySub(userId: string, payload: { sub: string; fingerprint: string }): Promise<void> {
  const remoteUserId = await resolveDecisionTarget(userId, payload.sub);

  await handleAcceptFingerprint(userId, { userId: remoteUserId, fingerprint: payload.fingerprint });
}

/** Boundary variant of {@link handleRefuseFingerprint} for callers holding a sub. */
export async function handleRefuseFingerprintBySub(userId: string, payload: { sub: string; fingerprint: string }): Promise<void> {
  const remoteUserId = await resolveDecisionTarget(userId, payload.sub);

  await handleRefuseFingerprint(userId, { userId: remoteUserId, fingerprint: payload.fingerprint });
}

/** All known (non-tombstoned) fingerprints with their status for this user. */
export async function handleGetKnownFingerprints(
  userId: string
): Promise<{ fingerprints: Record<string, { fingerprint: string; status: FingerprintStatus }> }> {
  const loaded = await loadVault(userId);
  const result: Record<string, { fingerprint: string; status: FingerprintStatus }> = {};

  for (const [remoteUserId, entry] of Object.entries(loaded?.state.tofu ?? {})) {
    if (entry.deleted) continue;

    result[remoteUserId] = { fingerprint: entry.fingerprint, status: entry.status };
  }

  return { fingerprints: result };
}
