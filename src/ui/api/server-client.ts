/**
 * Client for the encryption server API endpoints.
 * Errors from the server are returned as { code, params? } — the caller
 * translates them via translateApiError() from the i18n module.
 */
import { translateApiError } from '@encryption/src/i18n';
import type { VaultKeyringWire, VaultStoreBody } from '@encryption/src/shared/schemas/vault';

// In production, the interface and the API server share the same origin (encryption.xx).
// In dev, the Vite proxy forwards /api to the Fastify server.
const API_BASE = '';

export class ApiError extends Error {
  code: string;
  params?: Record<string, unknown>;
  status: number;

  constructor(status: number, code: string, params?: Record<string, unknown>) {
    const message = translateApiError({ code, params });
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.params = params;
    this.status = status;
  }
}

async function request<T>(path: string, options: RequestInit & { token?: string | null; xSignature?: string } = {}): Promise<T> {
  const { token, xSignature, ...fetchOptions } = options;

  const headers: Record<string, string> = {
    ...(fetchOptions.body ? { 'Content-Type': 'application/json' } : {}),
    ...(fetchOptions.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // Covered vault routes also require a per-request identity signature, produced
  // by the vault (the interface holds the token, not the identity key).
  if (xSignature) {
    headers['X-Signature'] = xSignature;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...fetchOptions,
    headers,
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));

    throw new ApiError(response.status, body.code ?? 'unknown', body.params);
  }

  return response.json() as Promise<T>;
}

// --- Public keys ---

/**
 * A registered identity as returned by the directory: both public keys plus
 * the binding signature and signed metadata. Consumers should verify the
 * binding (via `verifyKeyRegistration`) before trusting any field.
 */
export interface PublicKeyEntry {
  user_id: string;
  encryption_public_key: string;
  signature_public_key: string;
  key_binding_signature: string;
  version: number;
  created_at_millis: number;
}

export async function fetchPublicKeys(userIds: string[]): Promise<PublicKeyEntry[]> {
  const params = new URLSearchParams(userIds.map((userId) => ['user_ids', userId]));
  const result = await request<{ keys: PublicKeyEntry[] }>(`/api/public-keys?${params.toString()}`);

  return result.keys;
}

/**
 * Directory lookup by OIDC sub (unauthenticated, like every directory read).
 * Used before /api/me has resolved the internal id — e.g. the pre-login
 * "does this user already hold keys" check.
 */
export async function fetchPublicKeysBySubs(subs: string[]): Promise<Array<PublicKeyEntry & { sub?: string }>> {
  // Repeated `subs` parameters, never comma-joined: a sub may contain a comma.
  const params = new URLSearchParams(subs.map((sub) => ['subs', sub]));
  const result = await request<{ keys: Array<PublicKeyEntry & { sub?: string }> }>(`/api/public-keys?${params.toString()}`);

  return result.keys;
}

/**
 * Resolve the caller's OIDC session to the INTERNAL user id (minting the user
 * server-side on first contact). The interface threads this id into every
 * privileged vault flow: it is the id embedded in binding signatures.
 */
export async function fetchMe(token: string): Promise<{ userId: string; email: string | null }> {
  const result = await request<{ user_id: string; email: string | null }>('/api/me', { token });

  return { userId: result.user_id, email: result.email };
}

/**
 * Fetch the current active registered identity for a single user, or null if
 * none exists. Used to determine the next key version before registering.
 */
export async function fetchActivePublicKey(userId: string): Promise<PublicKeyEntry | null> {
  const keys = await fetchPublicKeys([userId]);

  return keys[0] ?? null;
}

export async function disablePublicKey(token: string): Promise<void> {
  await request<{ disabled: boolean }>('/api/public-keys', {
    method: 'DELETE',
    token,
  });
}

/**
 * The next monotonic version/generation the user must register, counting
 * disabled rows (numbers are never reused). Use this before signing a fresh key
 * so a re-onboard after a reset does not collide with an old version.
 */
export async function fetchNextKeyNumbers(token: string): Promise<{ next_version: number; next_generation: number }> {
  return request<{ next_version: number; next_generation: number }>('/api/public-keys/next', { token });
}

// Two-phase proof-of-possession registration. The caller orchestrates the
// round-trip, proving possession of BOTH the encryption and signature keys:
//   1. (vault) signKeyRegistration(version, createdAtMillis)  → signed bundle
//   2. initKeyPossession(token, submission)                   → { challengeId, ciphertext }
//   3. (vault) respondToKeyChallenge(challengeId, ciphertext) → { response, challengeSignature }
//   4. completeKeyPossession(token, challengeId, response, challengeSignature) → registered identity
// See src/crypto/key-possession-challenge.ts and src/crypto/key-registration.ts.

export interface InitKeyPossessionResult {
  challengeId: string;
  ciphertext: string;
}

export interface KeyRegistrationSubmission {
  userId: string;
  encryptionPublicKey: string;
  signaturePublicKey: string;
  version: number;
  createdAtMillis: number;
  keyBindingSignature: string;
}

export async function initKeyPossession(token: string, submission: KeyRegistrationSubmission): Promise<InitKeyPossessionResult> {
  const body = await request<{ challenge_id: string; ciphertext: string }>('/api/public-keys/register/init', {
    method: 'POST',
    token,
    body: JSON.stringify({
      user_id: submission.userId,
      encryption_public_key: submission.encryptionPublicKey,
      signature_public_key: submission.signaturePublicKey,
      version: submission.version,
      created_at_millis: submission.createdAtMillis,
      key_binding_signature: submission.keyBindingSignature,
    }),
  });

  return { challengeId: body.challenge_id, ciphertext: body.ciphertext };
}

export async function completeKeyPossession(
  token: string,
  challengeId: string,
  response: string,
  challengeSignature: string
): Promise<PublicKeyEntry> {
  return request<PublicKeyEntry>('/api/public-keys/register/complete', {
    method: 'POST',
    token,
    body: JSON.stringify({ challenge_id: challengeId, response, challenge_signature: challengeSignature }),
  });
}

// --- Synchronized vault ---

// One wire shape, defined once in the shared schema and enforced by the server.
export type VaultBootstrapBody = VaultStoreBody;

/**
 * Atomic onboarding: the directory registration (proof of possession) AND the
 * vault (keyring + sealed items + manifest) commit in one server transaction.
 */
export async function bootstrapVault(token: string, body: VaultBootstrapBody): Promise<{ revision: number }> {
  return request<{ revision: number }>('/api/vault', {
    method: 'POST',
    token,
    body: JSON.stringify(body),
  });
}

/** Change the recovery phrase: re-wrap only (the items are untouched). */
export async function updateVaultKeyring(token: string, keyring: VaultKeyringWire, xSignature: string): Promise<{ updated: boolean }> {
  return request<{ updated: boolean }>('/api/vault/keyring', {
    method: 'PUT',
    token,
    xSignature,
    body: JSON.stringify(keyring),
  });
}

// --- Device approval ---

export async function requestDeviceApproval(token: string, devicePublicKey: string): Promise<{ request_id: string }> {
  return request<{ request_id: string }>('/api/vault/approvals/request', {
    method: 'POST',
    token,
    body: JSON.stringify({ device_public_key: devicePublicKey }),
  });
}

/**
 * The path an approve call targets, exposed so the caller can obtain a matching
 * identity signature from the vault before invoking `approveDeviceOnServer`.
 */
export function approveDevicePath(requestId: string): string {
  return `/api/vault/approvals/${encodeURIComponent(requestId)}/approve`;
}

/** Enrolled device, manual fallback: this user's pending (unapproved) device requests. */
export async function listPendingApprovals(
  token: string,
  xSignature: string
): Promise<{ approvals: Array<{ request_id: string; device_public_key: string }> }> {
  return request<{ approvals: Array<{ request_id: string; device_public_key: string }> }>('/api/vault/approvals/pending', { token, xSignature });
}

export async function approveDeviceOnServer(
  token: string,
  requestId: string,
  wrappedDeviceBootstrap: string,
  xSignature: string
): Promise<{ approved: boolean }> {
  return request<{ approved: boolean }>(approveDevicePath(requestId), {
    method: 'POST',
    token,
    xSignature,
    body: JSON.stringify({ wrapped_device_bootstrap: wrappedDeviceBootstrap }),
  });
}

/** New device poll: returns the forwarded wrapped VRK, or null while still pending (425). */
export async function pollDeviceApproval(token: string, requestId: string): Promise<{ wrapped_device_bootstrap: string } | null> {
  try {
    return await request<{ wrapped_device_bootstrap: string }>(`/api/vault/approvals/${encodeURIComponent(requestId)}`, { token });
  } catch (err) {
    if (err instanceof ApiError && err.status === 425) return null;
    throw err;
  }
}

// --- Versions ---

export async function fetchVersions(): Promise<{ vault: string; ui: string; client: string }> {
  return request<{ vault: string; ui: string; client: string }>('/api/versions');
}
