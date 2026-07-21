/**
 * Resolution of the product-declared OIDC sub to the INTERNAL user id, at the
 * vault's message boundary. Everything past this point (cache keys, TOFU,
 * signed payloads, request proofs) speaks internal ids only.
 *
 * Fallback chain:
 *  1. in-memory map (one lookup per sub per page lifetime),
 *  2. IndexedDB alias store — written alongside the vault cache, so a cached
 *     vault always resolves offline,
 *  3. public registry lookup by sub (unauthenticated): covers a user with
 *     registered keys on a fresh browser, and the one online moment needed
 *     after an OIDC provider migration changed the sub,
 *  4. null — the user has no directory row (never onboarded), or the registry
 *     is unreachable and nothing is cached. The caller decides how to surface
 *     it (has-keys answers false; other operations fail with a stable code).
 *
 * The alias map is plain metadata, not a trust input: a hostile mapping can
 * only cause a cache miss or a failed sync (every server call is
 * independently authenticated, and trust decisions read the sealed TOFU
 * store), never a wrong trust or decryption outcome.
 */
import { getEncryptionDB } from '@encryption/src/crypto/encryption-db';
import { STORE_USER_ALIAS } from '@encryption/src/shared/constants';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

const API_BASE = '';

// A cached alias is trusted as long as it exists; there is deliberately NO
// background revalidation (normal operation never needs an own-sub network
// call once the alias is cached). Internal ids are immutable and never
// retired; the one thing that can move is the sub -> user MAPPING, by
// operator action (e.g. re-pointing a sub's oidc_accounts row from a
// duplicate user accidentally minted around a provider cutover back to the
// original account). No such tooling exists today, so an alias cannot
// actually go stale. If that tooling is ever built, invalidation here should
// be triggered by the data-plane's proof-subject-mismatch error code
// specifically, NOT by generic 401s (an expired token while offline would
// otherwise wipe a working alias).
const memoryAliases = new Map<string, string>();

/** Persist a sub -> internal id alias (memory + IndexedDB). Never throws. */
export async function rememberUserAlias(sub: string, internalUserId: string): Promise<void> {
  memoryAliases.set(sub, internalUserId);

  try {
    const db = await getEncryptionDB();
    await db.put(STORE_USER_ALIAS, internalUserId, sub);
  } catch {
    // Best-effort: memory still holds it for this page; next session re-resolves.
  }
}

async function readStoredAlias(sub: string): Promise<string | null> {
  try {
    const db = await getEncryptionDB();
    const value = (await db.get(STORE_USER_ALIAS, sub)) as string | undefined;

    return value ?? null;
  } catch {
    return null;
  }
}

async function resolveViaRegistry(sub: string): Promise<string | null> {
  try {
    const params = new URLSearchParams({ subs: sub });
    const response = await fetch(`${API_BASE}/api/public-keys?${params.toString()}`);
    if (!response.ok) return null;

    const data = (await response.json()) as { keys: Array<{ user_id: string; sub?: string }> };
    const match = data.keys.find((key) => key.sub === sub);

    return match?.user_id ?? null;
  } catch {
    return null;
  }
}

export async function resolveInternalUserId(sub: string): Promise<string | null> {
  const cached = memoryAliases.get(sub);
  if (cached) return cached;

  const stored = await readStoredAlias(sub);
  if (stored) {
    memoryAliases.set(sub, stored);

    return stored;
  }

  const fetched = await resolveViaRegistry(sub);
  if (fetched) {
    await rememberUserAlias(sub, fetched);

    return fetched;
  }

  return null;
}

/**
 * The message-boundary decision: which internal user id an incoming request
 * operates under.
 *
 * A declared internal id is adopted ONLY from privileged (interface-origin)
 * callers — the interface resolved it against the server with a real OIDC
 * session and is authoritative for its own id; adopting also refreshes the
 * sub -> id alias so later product-declared subs resolve offline. Everyone
 * else must declare a sub (a product sending only `internalUserId` is a
 * caller error, refused rather than resolved against `undefined`), which is
 * resolved through the alias/registry chain; null means "no encryption
 * account is known for this user".
 */
export async function resolveBoundaryUser(
  declaredSub: string | undefined,
  declaredInternalId: string | undefined,
  allowDeclaredInternalId: boolean
): Promise<string | null> {
  if (declaredInternalId && allowDeclaredInternalId) {
    if (declaredSub) {
      void rememberUserAlias(declaredSub, declaredInternalId);
    }

    return declaredInternalId;
  }

  if (!declaredSub) {
    throw new VaultError(VaultErrorCode.AUTH_REQUIRED, 'suiteUserId is required for all vault operations.');
  }

  return resolveInternalUserId(declaredSub);
}
