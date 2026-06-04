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

export interface PublicKeyEntry {
  user_id: string;
  public_key: string;
}

export async function fetchPublicKeys(userIds: string[]): Promise<PublicKeyEntry[]> {
  const result = await request<{ keys: PublicKeyEntry[] }>(`/api/public-keys?user_ids=${userIds.join(',')}`);

  return result.keys;
}

export async function disablePublicKey(token: string): Promise<void> {
  await request<{ disabled: boolean }>('/api/public-keys', {
    method: 'DELETE',
    token,
  });
}

// Two-phase proof-of-possession registration. The caller orchestrates
// the round-trip:
//   1. initKeyPossession(token, userId, publicKey)       → { challengeId, ciphertext }
//   2. (vault) respondToKeyChallenge(challengeId, ct)    → response
//   3. completeKeyPossession(token, challengeId, response) → registered key
// See src/crypto/key-possession-challenge.ts for the protocol details.

export interface InitKeyPossessionResult {
  challengeId: string;
  ciphertext: string;
}

export async function initKeyPossession(token: string, userId: string, publicKey: string): Promise<InitKeyPossessionResult> {
  const body = await request<{ challenge_id: string; ciphertext: string }>('/api/public-keys/register/init', {
    method: 'POST',
    token,
    body: JSON.stringify({ user_id: userId, public_key: publicKey }),
  });

  return { challengeId: body.challenge_id, ciphertext: body.ciphertext };
}

export async function completeKeyPossession(token: string, challengeId: string, response: string): Promise<PublicKeyEntry> {
  return request<PublicKeyEntry>('/api/public-keys/register/complete', {
    method: 'POST',
    token,
    body: JSON.stringify({ challenge_id: challengeId, response }),
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
