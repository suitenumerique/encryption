/**
 * Minimal Keycloak authentication for the demo pages.
 * Uses direct access grants (resource owner password) since this is a dev tool.
 * In production, suite products use the standard authorization code flow.
 *
 * Supports multiple users logged in simultaneously via a token store (Map).
 */

const KEYCLOAK_URL = 'http://localhost:7203';
const REALM = 'encryption';

// Select client credentials based on the demo port.
// Demo Product B runs on port 7202 and uses its own Keycloak client.
const isDemoProductB = window.location.port === '7202';
const CLIENT_ID = isDemoProductB ? 'demo-product-b' : 'demo-product-a';
const CLIENT_SECRET = isDemoProductB ? 'demo-product-b-secret' : 'encryption-dev-secret';

export interface DemoUser {
  id: string;
  username: string;
  firstName: string;
  lastName: string;
  email: string;
}

export const DEMO_USERS: DemoUser[] = [
  { id: '00000000-0000-0000-0000-000000000001', username: 'alice', firstName: 'Alice', lastName: 'Martin', email: 'alice.martin@numerique.gouv.fr' },
  { id: '00000000-0000-0000-0000-000000000002', username: 'bob', firstName: 'Bob', lastName: 'Dupont', email: 'bob.dupont@numerique.gouv.fr' },
  {
    id: '00000000-0000-0000-0000-000000000003',
    username: 'charlie',
    firstName: 'Charlie',
    lastName: 'Leroy',
    email: 'charlie.leroy@numerique.gouv.fr',
  },
  { id: '00000000-0000-0000-0000-000000000004', username: 'diane', firstName: 'Diane', lastName: 'Moreau', email: 'diane.moreau@numerique.gouv.fr' },
  { id: '00000000-0000-0000-0000-000000000005', username: 'emile', firstName: 'Emile', lastName: 'Petit', email: 'emile.petit@numerique.gouv.fr' },
];

interface TokenEntry {
  token: string;
  userId: string; // Keycloak sub claim
  expiresAt: number; // timestamp in ms
}

interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

// In-memory token store: username → token entry
const tokenStore = new Map<string, TokenEntry>();

// Persistent mapping: username → Keycloak sub (survives logout)
const knownUserIds = new Map<string, string>();

/** Get the Keycloak sub for a demo user (if they've logged in at least once). */
export function getKnownUserId(username: string): string | null {
  return knownUserIds.get(username) ?? null;
}

/**
 * Pre-resolve all demo users' Keycloak subs by doing a quick token fetch.
 * This populates the knownUserIds map so the Share modal can look up
 * public keys by real Keycloak sub instead of hardcoded demo IDs.
 * Tokens are fetched but NOT stored (only the sub mapping is kept).
 */
export async function resolveAllDemoUserIds(): Promise<void> {
  await Promise.allSettled(
    DEMO_USERS.map(async (user) => {
      if (knownUserIds.has(user.username)) return;

      try {
        const response = await fetch(`${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'password',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            username: user.username,
            password: 'password',
          }),
        });

        if (!response.ok) return;

        const data = (await response.json()) as TokenResponse;
        const userId = getUserIdFromToken(data.access_token);

        knownUserIds.set(user.username, userId);
      } catch {
        // Keycloak might not be available
      }
    })
  );
}

/**
 * Authenticate a demo user via Keycloak direct access grants.
 * Stores the token in the in-memory store.
 */
export async function loginUser(username: string): Promise<TokenEntry> {
  const response = await fetch(`${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      username,
      password: 'password',
    }),
  });

  if (!response.ok) {
    throw new Error(`Authentication failed for ${username}: ${response.status}`);
  }

  const data = (await response.json()) as TokenResponse;
  const userId = getUserIdFromToken(data.access_token);

  const entry: TokenEntry = {
    token: data.access_token,
    userId,
    expiresAt: Date.now() + data.expires_in * 1000,
  };

  tokenStore.set(username, entry);
  knownUserIds.set(username, userId);

  return entry;
}

/**
 * Logout a user: remove their token from the store.
 */
export function logoutUser(username: string): void {
  tokenStore.delete(username);
}

/**
 * Get the stored token for a user, or null if not logged in or expired.
 */
export function getToken(username: string): TokenEntry | null {
  const entry = tokenStore.get(username);

  if (!entry) return null;

  // Check expiry (with 30s buffer)
  if (Date.now() > entry.expiresAt - 30000) {
    tokenStore.delete(username);

    return null;
  }

  return entry;
}

/**
 * Check if a user is currently logged in with a valid token.
 */
export function isLoggedIn(username: string): boolean {
  return getToken(username) !== null;
}

/**
 * Get all currently logged-in usernames.
 */
export function getLoggedInUsers(): string[] {
  // Clean expired tokens first
  for (const [username] of tokenStore) {
    getToken(username);
  }

  return Array.from(tokenStore.keys());
}

/**
 * Decode the user ID (sub claim) from a JWT without verification.
 */
export function getUserIdFromToken(token: string): string {
  const payload = JSON.parse(atob(token.split('.')[1]));

  if (!payload.sub) {
    throw new Error('Token is missing the sub claim — ensure the Keycloak client has the "openid" scope');
  }

  return payload.sub as string;
}
