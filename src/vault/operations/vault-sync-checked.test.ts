import { beforeEach, describe, expect, it, vi } from 'vitest';

import { VaultErrorCode } from '@encryption/src/shared/vault-error';
import { reportVaultError } from '@encryption/src/vault/monitoring';
import { handleFetchPublicKeys } from '@encryption/src/vault/operations/fetch-public-keys';
import { INTEGRITY_RETRY_DELAY_MS, resetIntegrityReports, syncWithIntegrityRetry } from '@encryption/src/vault/operations/vault-sync-checked';
import { handleSync } from '@encryption/src/vault/operations/vault-sync-run';
import { loadVault } from '@encryption/src/vault/vault-keys';

vi.mock('@encryption/src/vault/operations/vault-sync-run', () => ({ handleSync: vi.fn() }));
vi.mock('@encryption/src/vault/operations/fetch-public-keys', () => ({ handleFetchPublicKeys: vi.fn() }));
vi.mock('@encryption/src/vault/vault-keys', () => ({ loadVault: vi.fn() }));
vi.mock('@encryption/src/vault/monitoring', () => ({ reportVaultError: vi.fn() }));
vi.mock('@encryption/src/crypto', () => ({ computeKeyFingerprint: vi.fn(async (key: string) => `fp-${key}`) }));
vi.mock('@encryption/src/crypto/vault-state', () => ({ activeIdentity: (state: { identity: unknown }) => state.identity }));

const USER_ID = 'user-1';
const delay = vi.fn(async () => undefined);

const ok = { status: 'ok', revision: 7 };
const broken = { status: 'integrity-error', revision: 7 };

function directoryIdentity(fingerprint: string | null) {
  vi.mocked(loadVault).mockResolvedValue({ state: { identity: { signaturePublicKey: 'local' } } } as never);
  vi.mocked(handleFetchPublicKeys).mockResolvedValue({
    users: fingerprint === null ? {} : { [USER_ID]: { identityFingerprint: fingerprint } },
  } as never);
}

beforeEach(() => {
  vi.clearAllMocks();
  resetIntegrityReports();
});

describe('syncWithIntegrityRetry', () => {
  it('returns a successful sync as is, with no retry', async () => {
    vi.mocked(handleSync).mockResolvedValueOnce(ok as never);

    expect(await syncWithIntegrityRetry(USER_ID, {}, { delay })).toEqual(ok);
    expect(handleSync).toHaveBeenCalledTimes(1);
    expect(delay).not.toHaveBeenCalled();
  });

  it('retries once after a pause and clears a passing failure without reporting it', async () => {
    vi.mocked(handleSync)
      .mockResolvedValueOnce(broken as never)
      .mockResolvedValueOnce(ok as never);

    expect(await syncWithIntegrityRetry(USER_ID, {}, { delay })).toEqual(ok);
    expect(delay).toHaveBeenCalledWith(INTEGRITY_RETRY_DELAY_MS);
    expect(handleSync).toHaveBeenCalledTimes(2);
    expect(reportVaultError).not.toHaveBeenCalled();
  });

  it('reports a lasting failure once when the identity still matches the directory', async () => {
    vi.mocked(handleSync).mockResolvedValue(broken as never);
    directoryIdentity('fp-local');

    expect(await syncWithIntegrityRetry(USER_ID, {}, { delay })).toEqual(broken);
    expect(await syncWithIntegrityRetry(USER_ID, {}, { delay })).toEqual(broken);

    expect(reportVaultError).toHaveBeenCalledTimes(1);
    expect(vi.mocked(reportVaultError).mock.calls[0][0]).toMatchObject({ code: VaultErrorCode.VAULT_INTEGRITY_FAILED });
  });

  it('classifies a different identity in the directory as a divergence, not a failure', async () => {
    vi.mocked(handleSync).mockResolvedValue(broken as never);
    directoryIdentity('fp-someone-else');

    expect(await syncWithIntegrityRetry(USER_ID, {}, { delay })).toEqual({ status: 'identity-diverged', revision: 7 });
    expect(reportVaultError).not.toHaveBeenCalled();
  });

  it('classifies an identity missing from the directory (disabled elsewhere) as a divergence', async () => {
    vi.mocked(handleSync).mockResolvedValue(broken as never);
    directoryIdentity(null);

    expect((await syncWithIntegrityRetry(USER_ID, {}, { delay })).status).toBe('identity-diverged');
    expect(reportVaultError).not.toHaveBeenCalled();
  });

  it('does not report when the directory cannot be reached', async () => {
    vi.mocked(handleSync).mockResolvedValue(broken as never);
    vi.mocked(loadVault).mockResolvedValue({ state: { identity: { signaturePublicKey: 'local' } } } as never);
    vi.mocked(handleFetchPublicKeys).mockRejectedValue(new Error('offline'));

    expect(await syncWithIntegrityRetry(USER_ID, {}, { delay })).toEqual(broken);
    expect(reportVaultError).not.toHaveBeenCalled();
  });
});
