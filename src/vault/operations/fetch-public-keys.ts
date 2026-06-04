/**
 * Fetch public keys from the encryption server API.
 *
 * This operation runs inside the vault iframe, which has direct access
 * to the encryption server (same origin or configured API). Products
 * call this via postMessage instead of making direct network calls
 * to the encryption server.
 */

// In production, the vault and the API server share the same origin (data.encryption.xx).
// The relative path works without a base URL. In dev, the Vite proxy forwards /api to the server.
const API_BASE = '';

export async function handleFetchPublicKeys(
  _userId: string,
  payload: { userIds: string[] },
): Promise<{ publicKeys: Record<string, ArrayBuffer> }> {
  if (!payload.userIds || payload.userIds.length === 0) {
    return { publicKeys: {} };
  }

  const response = await fetch(
    `${API_BASE}/api/public-keys?user_ids=${payload.userIds.join(',')}`,
  );

  if (!response.ok) {
    throw new Error(`Failed to fetch public keys: ${response.status}`);
  }

  const data = (await response.json()) as {
    keys: Array<{ user_id: string; public_key: string; algorithm: string }>;
  };

  // Convert base64 from the API to ArrayBuffer for the product
  const publicKeys: Record<string, ArrayBuffer> = {};

  for (const key of data.keys) {
    const binary = atob(key.public_key);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    publicKeys[key.user_id] = bytes.buffer as ArrayBuffer;
  }

  return { publicKeys };
}
