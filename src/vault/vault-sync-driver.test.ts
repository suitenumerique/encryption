import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  ensureVaultSyncDriver,
  isVaultSyncDriverHalted,
  resumeVaultSyncDriver,
  stopVaultSyncDriver,
  vaultSyncDriverOutcome,
} from '@encryption/src/vault/vault-sync-driver';

vi.mock('@encryption/src/crypto/encryption-backup', () => ({ base64ToUint8: () => new Uint8Array(32) }));
vi.mock('@encryption/src/crypto/request-proof', () => ({ REQUEST_SIG_HEADER: 'x-signature', signRequestProof: async () => 'sig' }));
vi.mock('@encryption/src/crypto/vault-state', () => ({ activeIdentity: () => ({ signatureSecretKey: 'c2VjcmV0' }) }));
vi.mock('@encryption/src/vault/vault-keys', () => ({ loadVault: async () => ({ state: {} }) }));
vi.mock('@encryption/src/vault/operations/vault-sync-run', () => ({ handleSync: vi.fn(async () => ({ status: 'ok', revision: 1 })) }));

const fetchMock = vi.fn<typeof fetch>();

// A never-ending event stream, as a healthy connection looks.
function openStream(): Response {
  const body = new ReadableStream<Uint8Array>({ start() {} });

  return new Response(body, { status: 200 });
}

async function settle(): Promise<void> {
  // Let the queued promise chain (auth header, catch-up sync, fetch) run.
  for (let i = 0; i < 10; i++) await Promise.resolve();
}

describe('vault sync driver', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    stopVaultSyncDriver();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('halts on a refused signature instead of retrying every few seconds', async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 401 }));

    ensureVaultSyncDriver('user-1');
    await settle();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(isVaultSyncDriverHalted()).toBe(true);

    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // Ordinary operations keep asking for the driver: they must not wake it.
    ensureVaultSyncDriver('user-1');
    await settle();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('tries again when resumed, after a privileged operation or a visible tab', async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 401 })).mockResolvedValue(openStream());

    ensureVaultSyncDriver('user-1');
    await settle();
    expect(isVaultSyncDriverHalted()).toBe(true);

    resumeVaultSyncDriver('user-1');
    await settle();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(isVaultSyncDriverHalted()).toBe(false);
  });

  it('tells a waiting courtesy call whether the identity got through', async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 401 }));
    ensureVaultSyncDriver('user-1');
    await expect(vaultSyncDriverOutcome()).resolves.toBe(false);

    fetchMock.mockResolvedValueOnce(openStream());
    resumeVaultSyncDriver('user-1');
    await expect(vaultSyncDriverOutcome()).resolves.toBe(true);
  });

  it('backs off exponentially on other failures, up to a minute', async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 503 }));

    ensureVaultSyncDriver('user-1');
    await settle();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // 3s, 6s, 12s, 24s, 48s, then 60s steps.
    for (const [elapsed, calls] of [
      [3_000, 2],
      [6_000, 3],
      [12_000, 4],
      [24_000, 5],
      [48_000, 6],
      [60_000, 7],
      [60_000, 8],
    ] as const) {
      await vi.advanceTimersByTimeAsync(elapsed);
      await settle();
      expect(fetchMock).toHaveBeenCalledTimes(calls);
    }
  });
});
