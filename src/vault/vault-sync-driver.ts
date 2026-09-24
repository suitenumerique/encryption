/**
 * Background sync driver, running INSIDE the vault iframe (which is loaded
 * whenever a product uses encryption, and holds the identity key). It keeps the
 * vault synced without the interface or an OIDC token: every request it makes is
 * authenticated by the identity signature alone (§7.1, tier 1).
 *
 * It is started lazily from the message handler the first time the vault handles
 * an op for a user (idempotent), so sync begins as soon as a product page is
 * open, and it:
 *   - does an initial pull (catch up a freshly opened / reloaded device), then
 *   - holds a long-lived SSE connection and re-syncs on each server "changed" wake.
 *
 * The SSE carries no vault data — just a wake — so a wake simply triggers the
 * normal authenticated pull.
 */
import { base64ToUint8 } from '@encryption/src/crypto/encryption-backup';
import { REQUEST_SIG_HEADER, signRequestProof } from '@encryption/src/crypto/request-proof';
import { activeIdentity } from '@encryption/src/crypto/vault-state';
import { handleSync } from '@encryption/src/vault/operations/vault-sync-run';
import { loadVault } from '@encryption/src/vault/vault-keys';

const EVENTS_PATH = '/api/vault/events';
const RECONNECT_MS = 3000;
const MAX_BACKOFF_MS = 60_000;

/**
 * `halted`: the server refused the identity signature. That is not a transient
 * condition a retry can clear (the identity is unknown to, or disabled on, this
 * server, which the settings screen explains to the user), so the driver stays
 * off until something that can change it happens: a privileged operation from
 * the interface, or the user coming back to the tab.
 */
let current: { userId: string; abort: AbortController; halted: boolean; outcome: Promise<boolean>; settle: (ok: boolean) => void } | null = null;

/**
 * Start (or re-target) the driver for `userId`. Idempotent for the same user;
 * switching users tears down the previous driver first. Fire-and-forget.
 */
export function ensureVaultSyncDriver(userId: string): void {
  if (current?.userId === userId) return;

  start(userId);
}

export function stopVaultSyncDriver(): void {
  current?.abort.abort();
  current = null;
}

/** Give a halted driver another chance; a running one is left alone. */
export function resumeVaultSyncDriver(userId: string): void {
  if (current?.userId === userId && !current.halted) return;

  start(userId);
}

/**
 * Whether the driver's first connection attempt for the current user got through
 * (true), or was refused or failed (false). A courtesy call that signs with the
 * same identity waits for this rather than making its own refused request.
 */
export function vaultSyncDriverOutcome(): Promise<boolean> {
  return current?.outcome ?? Promise.resolve(true);
}

/** For tests: whether the driver gave up on the current user. */
export function isVaultSyncDriverHalted(): boolean {
  return current?.halted ?? false;
}

function start(userId: string): void {
  stopVaultSyncDriver();
  const abort = new AbortController();
  let settle: (ok: boolean) => void = () => undefined;
  const outcome = new Promise<boolean>((resolve) => {
    settle = resolve;
  });
  current = { userId, abort, halted: false, outcome, settle };
  void drive(userId, abort.signal, settle);
}

async function drive(userId: string, signal: AbortSignal, settle: (ok: boolean) => void): Promise<void> {
  let delay = RECONNECT_MS;

  while (!signal.aborted) {
    try {
      // Only sync a COMMITTED (persisted) vault. During onboarding the vault is
      // only staged in memory and its identity is not registered server-side
      // yet, so every request would 401 until the user confirms their backup
      // (the commit that both persists locally and registers the identity).
      // `eventsAuthHeader` is null until then — we just wait and re-check on the
      // next backoff rather than spamming failed requests.
      const headers = await eventsAuthHeader(userId);

      if (!headers) settle(true); // Nothing to sign with: nothing was refused either.

      if (headers) {
        const res = await fetch(EVENTS_PATH, { headers, signal });

        if (res.status === 401 || res.status === 403) {
          if (current?.abort.signal === signal) current.halted = true;
          settle(false);

          return;
        }

        settle(res.ok);

        if (res.ok && res.body) {
          delay = RECONNECT_MS;

          // Catch-up pull once (re)connected: a wake could have fired (or another
          // instance handled the write) while we were disconnected, so the SSE
          // alone is never trusted to have delivered everything. After the
          // connect, not before, so a refused identity costs a single request.
          await safeSync(userId);

          const reader = res.body.getReader();
          const decoder = new TextDecoder();
          let buffer = '';

          while (!signal.aborted) {
            const { value, done } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });

            let sep: number;
            while ((sep = buffer.indexOf('\n\n')) !== -1) {
              const frame = buffer.slice(0, sep);
              buffer = buffer.slice(sep + 2);

              if (/(^|\n)event:\s*changed(\r?\n|$)/.test(frame)) void safeSync(userId);
            }
          }
        }
      }
    } catch {
      // Network drop / abort: reconnect below unless aborted.
      settle(false);
    }

    if (!signal.aborted) await backoff(delay, signal);
    delay = Math.min(delay * 2, MAX_BACKOFF_MS);
  }
}

// A pull that never rejects: not-enrolled or offline just means "try again on the
// next wake".
async function safeSync(userId: string): Promise<void> {
  try {
    await handleSync(userId);
  } catch {
    /* not enrolled yet / offline */
  }
}

// Sign the `GET /api/vault/events` request with the user's identity key. Null
// when the device holds no COMMITTED vault: `persistedOnly` skips a vault that
// is only staged in memory (mid-onboarding, before the user confirms their
// backup), whose identity the server has not registered yet — so the driver
// stays quiet instead of 401-ing until the commit lands.
async function eventsAuthHeader(userId: string): Promise<Record<string, string> | null> {
  const loaded = await loadVault(userId, { persistedOnly: true }).catch(() => null);
  const identity = loaded ? activeIdentity(loaded.state) : undefined;
  if (!identity) return null;

  const token = await signRequestProof({
    method: 'GET',
    path: EVENTS_PATH,
    userId,
    identitySecretKey: base64ToUint8(identity.signatureSecretKey),
    nowSeconds: Math.floor(Date.now() / 1000),
  });

  return { [REQUEST_SIG_HEADER]: token };
}

function backoff(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);

    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true }
    );
  });
}

// The PRIMARY convergence path (SSE is only a latency optimization): whenever the
// page becomes visible again — the user switching back to this tab, or turning to
// this device — pull immediately. This is what catches everything a missed SSE
// wake would not: a mutation handled by a different server instance, an instance
// restart, or a connection that was down. See architecture.md §8.
if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible' || !current) return;

    if (current.halted) resumeVaultSyncDriver(current.userId);
    else void safeSync(current.userId);
  });
}
