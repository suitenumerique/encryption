/**
 * HTTP implementation of the sync engine's SyncTransport, talking to the vault
 * routes on the same origin (data.encryption.xx). `fetch()` pulls the sealed
 * items + signed manifest; `putItem()` writes one item with optimistic
 * concurrency, mapping the server's 409 to the engine's `conflict` outcome.
 *
 * Both a JWT (owned by the interface, passed in per sync) AND a per-request
 * identity `X-Signature` are required: these are covered vault routes, so a bare
 * token cannot pull the sealed items. `signRequest` produces the signature for a
 * given method+path (see src/crypto/request-proof.ts); the caller wires it from
 * the vault's identity key.
 */
import { REQUEST_SIG_HEADER } from '@encryption/src/crypto/request-proof';
import type { SealedItem } from '@encryption/src/crypto/vault-manifest';
import type { PulledVault, PutItemInput, PutOutcome, SyncTransport } from '@encryption/src/vault/operations/vault-sync';

type FetchLike = typeof fetch;

interface ItemWire {
  item_id: string;
  type: string;
  ciphertext: string;
  revision_date_millis: number;
}

interface ItemsResponse {
  revision: number;
  manifest: string | null;
  manifest_sig: string | null;
  items: ItemWire[];
}

// In production the vault shares the API's origin, so a relative path works; in
// dev the Vite proxy forwards /api. Same convention as fetch-public-keys.ts.
const API_BASE = '';

// Bound every request so a hung/withholding server cannot hold the per-user vault
// cache lock (taken by the sync runner) indefinitely and wedge every other vault
// mutation across all tabs. A timeout aborts the fetch, which throws and releases
// the lock, and the sync simply retries on the next trigger.
const REQUEST_TIMEOUT_MS = 15000;

function requestTimeoutSignal(): AbortSignal | undefined {
  return typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(REQUEST_TIMEOUT_MS) : undefined;
}

function toSealed(w: ItemWire): SealedItem {
  // `type` is server-provided and covered by the signed manifest (verified when
  // the vault is opened), so we narrow it here; an unknown future type is ignored.
  return { id: w.item_id, type: w.type as SealedItem['type'], revisionDate: w.revision_date_millis, ciphertext: w.ciphertext };
}

export interface HttpSyncTransportOptions {
  token?: string | null;
  fetchImpl?: FetchLike;
  /** Produce the identity `X-Signature` proof for a request. Required for covered routes. */
  signRequest?: (method: string, path: string, body?: string) => Promise<string>;
}

export function createHttpSyncTransport({ token, fetchImpl = fetch, signRequest }: HttpSyncTransportOptions = {}): SyncTransport {
  const authHeaders: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};

  // JWT + (when a signer is provided) the per-request identity signature bound to
  // this exact method + path + body digest.
  async function headersFor(method: string, path: string, body: string, extra: Record<string, string> = {}): Promise<Record<string, string>> {
    const headers: Record<string, string> = { ...authHeaders, ...extra };

    if (signRequest) headers[REQUEST_SIG_HEADER] = await signRequest(method, path, body);

    return headers;
  }

  return {
    async fetch(): Promise<PulledVault | null> {
      const path = '/api/vault/items';
      const res = await fetchImpl(`${API_BASE}${path}`, {
        method: 'GET',
        headers: await headersFor('GET', path, ''),
        signal: requestTimeoutSignal(),
      });

      if (!res.ok) throw new Error(`Vault items fetch failed: ${res.status}`);

      const body = (await res.json()) as ItemsResponse;

      // An empty vault (never bootstrapped) reads as "no remote state".
      if (body.revision === 0 || body.manifest === null || body.manifest_sig === null) return null;

      return { sealed: body.items.map(toSealed), manifest: body.manifest, manifestSig: body.manifest_sig, revision: body.revision };
    },

    async putItem(input: PutItemInput): Promise<PutOutcome> {
      const path = `/api/vault/items/${encodeURIComponent(input.item.id)}`;
      // Serialize ONCE so the signed body digest and the sent body are identical.
      const reqBody = JSON.stringify({
        item: {
          item_id: input.item.id,
          type: input.item.type,
          ciphertext: input.item.ciphertext,
          revision_date_millis: input.item.revisionDate,
        },
        last_known_revision_date_millis: input.lastKnownRevisionDate,
        manifest: input.manifest,
        manifest_sig: input.manifestSig,
        revision: input.revision,
      });
      const res = await fetchImpl(`${API_BASE}${path}`, {
        method: 'PUT',
        headers: await headersFor('PUT', path, reqBody, { 'Content-Type': 'application/json' }),
        signal: requestTimeoutSignal(),
        body: reqBody,
      });

      // The server rejects a stale write with 409; the engine retries the whole
      // pull-merge-push loop.
      if (res.status === 409) return { ok: false, conflict: true };

      if (!res.ok) throw new Error(`Vault item put failed: ${res.status}`);

      const body = (await res.json()) as { revision: number };

      return { ok: true, revision: body.revision };
    },
  };
}
