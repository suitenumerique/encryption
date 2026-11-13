/**
 * @vitest-environment jsdom
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';
import { reportVaultError, resetVaultErrorReporting, shouldReportVaultError } from '@encryption/src/vault/monitoring';

describe('shouldReportVaultError', () => {
  it('reports unexpected throws and integrity failures, not normal outcomes', () => {
    expect(shouldReportVaultError(new TypeError('x'))).toBe(true);
    expect(shouldReportVaultError('string')).toBe(true);
    expect(shouldReportVaultError(new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'x'))).toBe(true);
    expect(shouldReportVaultError(new VaultError(VaultErrorCode.INVALID_KEY_BINDING, 'x'))).toBe(true);

    expect(shouldReportVaultError(new VaultError(VaultErrorCode.MISSING_KEYS, 'x'))).toBe(false);
    expect(shouldReportVaultError(new VaultError(VaultErrorCode.WRONG_SECRET_KEY, 'x'))).toBe(false);
    expect(shouldReportVaultError(new VaultError(VaultErrorCode.UNKNOWN, 'x'))).toBe(false);
  });
});

describe('reportVaultError', () => {
  const fetchMock = vi.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    resetVaultErrorReporting();
    fetchMock.mockClear();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // The vault instance of the shared reporter is the one with text switched off.
  it('sends the name, the code and the frames, and never a message or a path', () => {
    reportVaultError(new VaultError(VaultErrorCode.VAULT_INTEGRITY_FAILED, 'the phrase was correct horse battery staple'));

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);

    expect(body).toEqual({ type: 'browser-error', name: 'VaultError', code: 'VAULT_INTEGRITY_FAILED', frames: [] });
  });
});
