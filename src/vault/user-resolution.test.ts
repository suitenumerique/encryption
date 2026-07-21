import { STORE_USER_ALIAS } from '@encryption/src/shared/constants';
import { VaultErrorCode } from '@encryption/src/shared/vault-error';
import { rememberUserAlias, resolveBoundaryUser, resolveInternalUserId } from '@encryption/src/vault/user-resolution';

const mockDbGet = jest.fn();
const mockDbPut = jest.fn();

jest.mock('@encryption/src/crypto/encryption-db', () => ({
  getEncryptionDB: async () => ({ get: mockDbGet, put: mockDbPut }),
}));

const mockFetch = jest.fn();

// The registry answer for one sub, as /api/public-keys?subs= would shape it.
function registryHit(sub: string, userId: string) {
  return { ok: true, json: async () => ({ keys: [{ user_id: userId, sub }] }) };
}

const registryMiss = { ok: true, json: async () => ({ keys: [] }) };

// The revalidation write-back runs as a detached promise chain; let it settle.
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

beforeAll(() => {
  global.fetch = mockFetch as unknown as typeof fetch;
});

beforeEach(() => {
  jest.clearAllMocks();
  mockDbGet.mockResolvedValue(undefined);
  mockDbPut.mockResolvedValue(undefined);
  mockFetch.mockResolvedValue(registryMiss);
});

// The module keeps per-page memory (alias map + revalidation set), so every
// test uses its own sub to stay independent.
describe('resolveInternalUserId', () => {
  it('answers from the stored alias even when the registry is unreachable', async () => {
    mockDbGet.mockResolvedValue('internal-a');
    mockFetch.mockRejectedValue(new Error('offline'));

    await expect(resolveInternalUserId('sub-offline')).resolves.toBe('internal-a');
  });

  it('falls back to the registry and persists the alias it learned', async () => {
    mockFetch.mockResolvedValue(registryHit('sub-fresh', 'internal-b'));

    await expect(resolveInternalUserId('sub-fresh')).resolves.toBe('internal-b');
    expect(mockDbPut).toHaveBeenCalledWith(STORE_USER_ALIAS, 'internal-b', 'sub-fresh');
  });

  it('returns null when nothing is cached and the registry has no row', async () => {
    await expect(resolveInternalUserId('sub-nobody')).resolves.toBeNull();
    expect(mockDbPut).not.toHaveBeenCalled();
  });

  it('never touches the network once an alias is cached (no background revalidation)', async () => {
    mockDbGet.mockResolvedValue('internal-cached');

    await expect(resolveInternalUserId('sub-cached')).resolves.toBe('internal-cached');
    await expect(resolveInternalUserId('sub-cached')).resolves.toBe('internal-cached');
    await flush();

    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe('resolveBoundaryUser', () => {
  it('adopts a privileged caller-declared internal id and refreshes the alias', async () => {
    await expect(resolveBoundaryUser('sub-iface', 'internal-iface', true)).resolves.toBe('internal-iface');

    await flush();
    expect(mockDbPut).toHaveBeenCalledWith(STORE_USER_ALIAS, 'internal-iface', 'sub-iface');
  });

  it('refuses a non-privileged caller that declares only an internal id (no resolution attempt against undefined)', async () => {
    await expect(resolveBoundaryUser(undefined, 'internal-sneaky', false)).rejects.toMatchObject({ code: VaultErrorCode.AUTH_REQUIRED });
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('ignores the declared internal id for non-privileged callers and resolves their sub instead', async () => {
    mockFetch.mockResolvedValue(registryHit('sub-prod', 'internal-real'));

    await expect(resolveBoundaryUser('sub-prod', 'internal-claimed', false)).resolves.toBe('internal-real');
  });

  it('requires a sub when no internal id is declared', async () => {
    await expect(resolveBoundaryUser(undefined, undefined, true)).rejects.toMatchObject({ code: VaultErrorCode.AUTH_REQUIRED });
  });
});

describe('rememberUserAlias', () => {
  it('survives a failing IndexedDB write (memory still answers this page)', async () => {
    mockDbPut.mockRejectedValue(new Error('quota'));

    await rememberUserAlias('sub-mem', 'internal-mem');

    mockDbGet.mockResolvedValue(undefined);
    await expect(resolveInternalUserId('sub-mem')).resolves.toBe('internal-mem');
  });
});
