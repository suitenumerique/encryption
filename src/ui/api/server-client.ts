/**
 * Client for the encryption server API endpoints.
 * Errors from the server are returned as { code, params? } — the caller
 * translates them via translateApiError() from the i18n module.
 */
import { translateApiError } from '@encryption/src/i18n';

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

async function request<T>(path: string, options: RequestInit & { token?: string | null } = {}): Promise<T> {
  const { token, ...fetchOptions } = options;

  const headers: Record<string, string> = {
    ...(fetchOptions.body ? { 'Content-Type': 'application/json' } : {}),
    ...(fetchOptions.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
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
  const userIdsParam = userIds.map(encodeURIComponent).join(',');
  const result = await request<{ keys: PublicKeyEntry[] }>(`/api/public-keys?user_ids=${userIdsParam}`);

  return result.keys;
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

// --- Device transfer ---

export interface TransferSession {
  code: string;
  expiresAt: string;
}

export async function initiateDeviceTransfer(token: string, encryptedPayload: string): Promise<TransferSession> {
  return request<TransferSession>('/api/device-transfer/initiate', {
    method: 'POST',
    token,
    body: JSON.stringify({ encryptedPayload }),
  });
}

export async function claimDeviceTransfer(token: string, code: string): Promise<{ encryptedPayload: string }> {
  return request<{ encryptedPayload: string }>('/api/device-transfer/claim', {
    method: 'POST',
    token,
    body: JSON.stringify({ code }),
  });
}

export async function pollDeviceTransfer(token: string, code: string): Promise<{ status: 'pending' | 'claimed' | 'expired'; expiresAt?: string }> {
  return request<{ status: 'pending' | 'claimed' | 'expired'; expiresAt?: string }>(`/api/device-transfer/poll/${code}`, {
    token,
  });
}

// --- Versions ---

export async function fetchVersions(): Promise<{ vault: string; ui: string; client: string }> {
  return request<{ vault: string; ui: string; client: string }>('/api/versions');
}
