/**
 * Persist the provider's ID token in the interface's own localStorage, ONE PER
 * SUITE USER.
 *
 * Keyed by `suiteUserId` (the OIDC sub the product says is signed in), which is
 * what lets several people share a browser profile: each product page asks for
 * the ID token of the user IT has signed in, and one issued to someone else is
 * never picked up. A cookie could not do this: the browser would send every
 * user's cookie, or the last one set, without the product's user ever choosing
 * between them.
 *
 * ID tokens belong to the interface domain (encryption), not the vault
 * (data.encryption). The vault stores only private keys and crypto — keeping auth
 * tokens there would break the architectural separation of concerns.
 *
 * localStorage is partitioned by the EMBEDDING page's top-level site (Chrome 115+),
 * and every product is required to share one registrable domain (see the storage
 * partitioning constraint in the README), so they all land in the SAME partition:
 * one ID token shared across the suite, not one per product. Signing in from one
 * product therefore leaves the others signed in.
 *
 * A product deployed outside that domain would get a bucket of its own, but it would
 * also lose the shared vault keys, so that is a broken deployment rather than a
 * supported mode.
 */
import { type IdTokenSet, idTokenSetSchema } from '@encryption/src/ui/auth/login';

const STORAGE_KEY_PREFIX = 'encryption-id-token:';

export function storeIdTokenSet(suiteUserId: string, idTokenSet: IdTokenSet): void {
  try {
    localStorage.setItem(STORAGE_KEY_PREFIX + suiteUserId, JSON.stringify(idTokenSet));
  } catch {
    // localStorage might be unavailable in some sandboxed contexts
  }
}

export function readIdTokenSet(suiteUserId: string): IdTokenSet | null {
  try {
    return parseIdTokenSet(localStorage.getItem(STORAGE_KEY_PREFIX + suiteUserId));
  } catch {
    return null;
  }
}

/**
 * Call `onStored` whenever ANOTHER page of the same storage partition stores an
 * ID token for this suite user (the browser fires `storage` events in every
 * document but the writer), so one sign-in leaves every open interface signed in.
 * Returns the unsubscribe function.
 */
export function subscribeToIdTokenSet(suiteUserId: string, onStored: (idTokenSet: IdTokenSet) => void): () => void {
  const key = STORAGE_KEY_PREFIX + suiteUserId;

  function handleStorage(event: StorageEvent) {
    if (event.key !== key || event.storageArea !== localStorage) return;

    const idTokenSet = parseIdTokenSet(event.newValue);

    if (idTokenSet) onStored(idTokenSet);
  }

  window.addEventListener('storage', handleStorage);

  return () => window.removeEventListener('storage', handleStorage);
}

function parseIdTokenSet(raw: string | null): IdTokenSet | null {
  if (!raw) return null;

  try {
    const parsed = idTokenSetSchema.safeParse(JSON.parse(raw));

    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export function clearIdTokenSet(suiteUserId: string): void {
  try {
    localStorage.removeItem(STORAGE_KEY_PREFIX + suiteUserId);
  } catch {
    // Best effort
  }
}
