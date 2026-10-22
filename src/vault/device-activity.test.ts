import 'fake-indexeddb/auto';
import sodium from 'libsodium-wrappers-sumo';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { getEncryptionDB } from '@encryption/src/crypto/encryption-db';
import { BROADCAST_CHANNEL_NAME, BROADCAST_KEYS_DESTROYED, STORE_DEVICE_ACTIVITY, STORE_VAULT_CACHE } from '@encryption/src/shared/constants';
import { closeVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { expireInactiveVaults, recordDeviceUse } from '@encryption/src/vault/device-activity';
import { handleCommitStagedVault, handleUncommitStagedVault } from '@encryption/src/vault/operations/commit-staged';
import { handleDestroyKeys } from '@encryption/src/vault/operations/destroy-keys';
import { handleGenerateKeys } from '@encryption/src/vault/operations/generate-keys';
import { handleHasKeys } from '@encryption/src/vault/operations/key-management';
import { getCachedSymmetricKey, setCachedSymmetricKey } from '@encryption/src/vault/symmetric-key-cache';
import { type VaultCacheEntry, saveVaultCache } from '@encryption/src/vault/vault-cache';

const config = vi.hoisted(() => ({ deviceInactivityDays: 365 }));
vi.mock('@encryption/src/vault/runtime-config', () => ({ runtimeConfig: config }));

const DAY_MS = 24 * 60 * 60 * 1000;

beforeAll(async () => {
  await sodium.ready;
});

afterAll(() => {
  closeVaultBroadcastChannel();
});

beforeEach(() => {
  config.deviceInactivityDays = 365;
});

async function enrolledVault(userId: string) {
  await handleGenerateKeys(userId);
  await handleCommitStagedVault(userId);
}

async function activityOf(userId: string) {
  return (await getEncryptionDB()).get(STORE_DEVICE_ACTIVITY, userId);
}

async function cacheOf(userId: string): Promise<VaultCacheEntry | undefined> {
  return (await getEncryptionDB()).get(STORE_VAULT_CACHE, userId);
}

async function lastUsed(userId: string, daysAgo: number, nowMs = Date.now()) {
  await (await getEncryptionDB()).put(STORE_DEVICE_ACTIVITY, { lastUsedAt: nowMs - daysAgo * DAY_MS }, userId);
}

describe('recording a use', () => {
  it('dates the vault when it is enrolled, not while it is only staged', async () => {
    await handleGenerateKeys('u-enroll');
    await recordDeviceUse('u-enroll');
    expect(await activityOf('u-enroll')).toBeUndefined();

    await handleCommitStagedVault('u-enroll');
    expect((await activityOf('u-enroll')).lastUsedAt).toBeGreaterThan(Date.now() - DAY_MS);
  });

  it('records an operation at most once a day per vault context', async () => {
    const now = Date.now();
    await enrolledVault('u-daily');
    await lastUsed('u-daily', 2, now);

    await recordDeviceUse('u-daily', now);
    expect((await activityOf('u-daily')).lastUsedAt).toBe(now);

    await lastUsed('u-daily', 2, now);
    await recordDeviceUse('u-daily', now + DAY_MS - 1);
    expect((await activityOf('u-daily')).lastUsedAt).toBe(now - 2 * DAY_MS);

    await recordDeviceUse('u-daily', now + DAY_MS);
    expect((await activityOf('u-daily')).lastUsedAt).toBe(now + DAY_MS);
  });

  it('checks the delay before recording, so a late use never revives a stale vault', async () => {
    await enrolledVault('u-late');
    await lastUsed('u-late', 400);

    await recordDeviceUse('u-late');

    expect(await cacheOf('u-late')).toBeUndefined();
    expect((await activityOf('u-late')).deEnrolledAt).toBeDefined();
  });

  it('starts the clock of a vault found with no recorded use', async () => {
    await enrolledVault('u-undated');
    await (await getEncryptionDB()).delete(STORE_DEVICE_ACTIVITY, 'u-undated');

    await recordDeviceUse('u-undated');

    expect((await activityOf('u-undated')).lastUsedAt).toBeGreaterThan(Date.now() - DAY_MS);
  });
});

describe('forgetting after inactivity', () => {
  it('keeps a vault used exactly at the delay, forgets it one millisecond later', async () => {
    const now = Date.now();
    await enrolledVault('u-edge');
    await lastUsed('u-edge', 365, now);

    await expireInactiveVaults(now);
    expect(await cacheOf('u-edge')).toBeDefined();

    await expireInactiveVaults(now + 1);
    expect(await cacheOf('u-edge')).toBeUndefined();
  });

  it('forgets a vault left unused past the delay on read, and says why', async () => {
    await enrolledVault('u-stale');
    await lastUsed('u-stale', 366);

    const result = await handleHasKeys('u-stale');

    expect(result).toEqual({ hasKeys: false, deEnrolled: { deEnrolledAt: expect.any(Number), inactivityDays: 365 } });
    expect(await cacheOf('u-stale')).toBeUndefined();
  });

  it('empties the decrypted-key cache and tells the other tabs, like leaving encryption', async () => {
    await enrolledVault('u-aftermath');
    await lastUsed('u-aftermath', 400);
    setCachedSymmetricKey('u-aftermath', new Uint8Array([1, 2, 3]), new Uint8Array(32));

    const otherTab = new BroadcastChannel(BROADCAST_CHANNEL_NAME);
    const received = new Promise((resolve) => (otherTab.onmessage = (event) => resolve(event.data)));

    await handleHasKeys('u-aftermath');

    expect(getCachedSymmetricKey('u-aftermath', new Uint8Array([1, 2, 3]))).toBeNull();
    expect(await received).toEqual({ type: BROADCAST_KEYS_DESTROYED });
    otherTab.close();
  });

  it('sweeps every user of the browser at load: forgets the stale, keeps the recent, dates the undated', async () => {
    await enrolledVault('u-sweep-stale');
    await lastUsed('u-sweep-stale', 500);
    await enrolledVault('u-sweep-recent');
    await lastUsed('u-sweep-recent', 10);
    await enrolledVault('u-sweep-undated');
    await (await getEncryptionDB()).delete(STORE_DEVICE_ACTIVITY, 'u-sweep-undated');

    await expireInactiveVaults();

    expect(await cacheOf('u-sweep-stale')).toBeUndefined();
    expect(await cacheOf('u-sweep-recent')).toBeDefined();
    expect((await activityOf('u-sweep-recent')).lastUsedAt).toBeLessThan(Date.now() - 9 * DAY_MS);
    expect((await activityOf('u-sweep-undated')).lastUsedAt).toBeGreaterThan(Date.now() - DAY_MS);
  });

  it('never forgets when the delay is off', async () => {
    await enrolledVault('u-off');
    await lastUsed('u-off', 5000);
    config.deviceInactivityDays = 0;

    expect((await handleHasKeys('u-off')).hasKeys).toBe(true);
  });
});

describe('enrolling again', () => {
  it('drops the notice when the vault is generated again', async () => {
    await enrolledVault('u-back');
    await lastUsed('u-back', 400);
    expect((await handleHasKeys('u-back')).deEnrolled).toBeDefined();

    await enrolledVault('u-back');

    expect(await handleHasKeys('u-back')).toEqual({ hasKeys: true });
  });

  it('drops the notice when a restore or a pairing writes the vault', async () => {
    await enrolledVault('u-restore');
    const entry = (await cacheOf('u-restore'))!;
    await lastUsed('u-restore', 400);
    expect((await handleHasKeys('u-restore')).deEnrolled).toBeDefined();

    await saveVaultCache('u-restore', entry);

    expect(await handleHasKeys('u-restore')).toEqual({ hasKeys: true });
  });
});

describe('leaving no trace', () => {
  it('when the user leaves encryption', async () => {
    await enrolledVault('u-leave');
    await handleDestroyKeys('u-leave');

    expect(await activityOf('u-leave')).toBeUndefined();
  });

  it('when a failed registration moves the vault back to memory', async () => {
    await enrolledVault('u-uncommit');
    await handleUncommitStagedVault('u-uncommit');

    expect(await cacheOf('u-uncommit')).toBeUndefined();
    expect(await activityOf('u-uncommit')).toBeUndefined();
  });
});
