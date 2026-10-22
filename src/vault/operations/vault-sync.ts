/**
 * The sync engine: pull, verify, merge, then push local changes write-through.
 *
 * All I/O is behind `SyncTransport` so the orchestration is testable without a
 * server or a browser. The flow: fetch the server's sealed vault, verify it
 * against the trusted identity (refuse on tamper/rollback), merge it with local
 * state, then push each changed item. Each push carries a manifest covering the
 * item set as it will be *after* that write, so every committed state stays
 * consistent. A 409 means the server moved under us; the caller re-runs, and
 * because the merge is idempotent the local change is simply re-applied.
 */
import type { SealedItem } from '@encryption/src/crypto/vault-manifest';
import { buildSignedManifest, openState, sealItem, verifyPulledVault } from '@encryption/src/crypto/vault-seal';
import { type VaultState, emptyVaultState, mergeVaultState } from '@encryption/src/crypto/vault-state';
import { planPush } from '@encryption/src/vault/operations/vault-sync-planner';

export interface PulledVault {
  sealed: SealedItem[];
  manifest: string;
  manifestSig: string;
  revision: number;
}

export type PutOutcome = { ok: true; revision: number } | { ok: false; conflict: true };

export interface PutItemInput {
  item: SealedItem;
  lastKnownRevisionDate: number | null;
  manifest: string;
  manifestSig: string;
  revision: number;
}

export interface SyncTransport {
  fetch(): Promise<PulledVault | null>;
  putItem(input: PutItemInput): Promise<PutOutcome>;
}

export interface SyncCrypto {
  vrk: Uint8Array;
  identitySecretKey: Uint8Array;
  trustedIdentityPublicKey: Uint8Array;
  identityGen: number;
}

export type SyncResult = { status: 'ok'; state: VaultState; revision: number } | { status: 'integrity-error' } | { status: 'conflict' };

export async function syncOnce(local: VaultState, lastSeenRevision: number, transport: SyncTransport, crypto: SyncCrypto): Promise<SyncResult> {
  const pulled = await transport.fetch();

  let remoteState = emptyVaultState();
  let serverRevision = 0;
  const cumulative = new Map<string, SealedItem>();

  if (pulled) {
    // NOTE: `integrity-error` currently also absorbs a LEGITIMATE case: the user
    // ran start-over or /reactivate on another device, so the active vault's
    // identity (or its revision baseline) changed and this device's pull no longer
    // verifies against the identity it locally trusts. Distinguishing "validly
    // signed by a DIFFERENT identity" (a candidate legit switch, route to
    // reconciliation) from "same identity, rolled back or bad coverage" (tamper)
    // belongs to the identity reconciliation effort (see
    // project_identity_reconciliation), which owns the recovery UI. Until that
    // lands, both fail closed here rather than silently adopting.
    if (!(await verifyPulledVault(pulled.sealed, pulled.manifest, pulled.manifestSig, crypto.trustedIdentityPublicKey, lastSeenRevision))) {
      return { status: 'integrity-error' };
    }
    remoteState = await openState(pulled.sealed, crypto.vrk);
    serverRevision = pulled.revision;
    for (const s of pulled.sealed) cumulative.set(s.id, s);
  } else if (lastSeenRevision > 0) {
    // The server presented an empty vault to a device that has already seen a
    // real revision. That is a rollback (tamper or data loss), not a first
    // push: treating it as empty would silently re-push local state at a reset
    // revision and drop whatever other devices contributed. Refuse.
    return { status: 'integrity-error' };
  }

  const merged = mergeVaultState(local, remoteState);
  const pushes = planPush(remoteState, merged);

  if (pushes.length === 0) return { status: 'ok', state: merged, revision: serverRevision };

  let revision = serverRevision;

  for (const push of pushes) {
    const sealed = await sealItem(push.item, crypto.vrk);
    cumulative.set(sealed.id, sealed);
    revision += 1;

    const sentRevision = revision;
    const { manifest, manifestSig } = await buildSignedManifest(sentRevision, crypto.identityGen, [...cumulative.values()], crypto.identitySecretKey);
    const outcome = await transport.putItem({
      item: sealed,
      lastKnownRevisionDate: push.lastKnownRevisionDate,
      manifest,
      manifestSig,
      revision: sentRevision,
    });

    if (!outcome.ok) return { status: 'conflict' };

    // The server must acknowledge exactly the revision we committed to (the CAS
    // sets accountRevision to the value we sent). A different ack, in particular a
    // lower one, would mean the server is trying to get us to sign a SECOND,
    // different manifest at a revision it can also serve elsewhere (equivocation).
    // Refuse rather than trust the returned number.
    if (outcome.revision !== sentRevision) return { status: 'integrity-error' };
    revision = outcome.revision;
  }

  return { status: 'ok', state: merged, revision };
}

/** Retry the pull-merge-push loop on a 409 (the server advanced under us). */
export async function sync(
  local: VaultState,
  lastSeenRevision: number,
  transport: SyncTransport,
  crypto: SyncCrypto,
  maxAttempts = 3
): Promise<SyncResult> {
  let result: SyncResult = { status: 'conflict' };

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    result = await syncOnce(local, lastSeenRevision, transport, crypto);
    if (result.status !== 'conflict') return result;
  }

  return result;
}
