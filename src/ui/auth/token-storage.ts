/**
 * Persist OIDC tokens in the interface's own localStorage.
 *
 * Tokens belong to the interface domain (encryption), not the vault (data.encryption).
 * The vault stores only private keys and crypto — keeping auth tokens there would
 * break the architectural separation of concerns.
 *
 * localStorage is partitioned by the EMBEDDING page's top-level site (Chrome 115+),
 * and every product is required to share one registrable domain (see the storage
 * partitioning constraint in the README), so they all land in the SAME partition:
 * one token session shared across the suite, not one per product. Signing in from
 * one product therefore leaves the others signed in. The `suiteUserId` in the key is
 * what separates users, not products.
 *
 * A product deployed outside that domain would get a bucket of its own, but it would
 * also lose the shared vault keys, so that is a broken deployment rather than a
 * supported mode.
 */
import { type TokenSet, tokenSetSchema } from '@encryption/src/ui/auth/oidc-client';

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

    const parsed = tokenSetSchema.safeParse(JSON.parse(raw));

    return parsed.success ? parsed.data : null;
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
