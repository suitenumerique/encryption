/**
 * Persist OIDC tokens in the interface's own localStorage.
 *
 * Tokens belong to the interface domain (encryption), not the vault (data.encryption).
 * The vault stores only private keys and crypto — keeping auth tokens there would
 * break the architectural separation of concerns.
 *
 * Note: localStorage is partitioned per top-level site (Chrome 115+), so each
 * product embedding gets its own token session. This is acceptable — the OIDC
 * session is per-product anyway.
 */

import type { TokenSet } from '@encryption/src/ui/auth/oidc-client';

const STORAGE_KEY_PREFIX = 'encryption-oidc-token:';

export function storeToken(suiteUserId: string, tokenSet: TokenSet): void {
  try {
    localStorage.setItem(STORAGE_KEY_PREFIX + suiteUserId, JSON.stringify(tokenSet));
  } catch {
    // localStorage might be unavailable in some sandboxed contexts
  }
}

export function readToken(suiteUserId: string): TokenSet | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_PREFIX + suiteUserId);

    if (!raw) return null;

    return JSON.parse(raw) as TokenSet;
  } catch {
    return null;
  }
}

export function clearToken(suiteUserId: string): void {
  try {
    localStorage.removeItem(STORAGE_KEY_PREFIX + suiteUserId);
  } catch {
    // Best effort
  }
}
