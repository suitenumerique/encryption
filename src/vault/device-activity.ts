/**
 * De-enroll after inactivity: a browser that has not used a user's vault for
 * VAULT_DEVICE_INACTIVITY_DAYS forgets its copy (device key, wrapped VRK, sealed
 * items), so it must be enrolled again with another device or the recovery
 * phrase. It protects a device lost and found after that delay, not one an
 * attacker uses before it.
 *
 * A use is any operation the message handler runs for the user
 * ({@link recordDeviceUse}, warm decrypts included) and any write of the vault
 * to disk (vault-cache.ts). The delay is checked before each of them, on every
 * read of the persisted cache, and for every user of this browser when the vault
 * loads, so a shared computer also forgets the users who stopped coming. A vault
 * found with no recorded use starts its clock then.
 */
import { getEncryptionDB } from '@encryption/src/crypto/encryption-db';
import { BROADCAST_KEYS_DESTROYED, STORE_DEVICE_ACTIVITY, STORE_VAULT_CACHE } from '@encryption/src/shared/constants';
import type { DeEnrollment } from '@encryption/src/shared/has-keys';
import { getVaultBroadcastChannel } from '@encryption/src/vault/broadcast';
import { runtimeConfig } from '@encryption/src/vault/runtime-config';
import { clearSymmetricKeyCache } from '@encryption/src/vault/symmetric-key-cache';

const DAY_MS = 24 * 60 * 60 * 1000;

export interface DeviceActivity {
  lastUsedAt?: number;
  // Set when the vault was forgotten, until the next enrollment overwrites it.
  deEnrolledAt?: number;
  inactivityDays?: number;
}

// The block is absent only without a server (Storybook, unit tests): one the
// server served is validated in full at load. Absent then means never forget,
// rather than deleting keys on a guessed delay.
function inactivityDays(): number {
  return runtimeConfig.deviceInactivityDays ?? 0;
}

export function isPastInactivityDelay(activity: DeviceActivity | undefined, nowMs = Date.now()): boolean {
  const days = inactivityDays();

  return days > 0 && activity?.lastUsedAt !== undefined && nowMs - activity.lastUsedAt > days * DAY_MS;
}

export function usedAt(nowMs = Date.now()): DeviceActivity {
  return { lastUsedAt: nowMs };
}

// Users this vault context recorded a use for, and when: every operation of a
// product (each WebSocket message decrypts) would otherwise open a transaction,
// for a delay counted in months.
const recordedUses = new Map<string, number>();

export function forgetRecordedUse(userId: string): void {
  recordedUses.delete(userId);
}

/**
 * Check the delay then record a use, in one transaction so no use from another
 * tab can land between the two. `record: 'start-clock'` only dates a vault that
 * has no recorded use yet (the sweep, for users who are not here). Returns true
 * when the vault was forgotten.
 */
async function checkActivity(userId: string, record: 'use' | 'start-clock' | 'none', nowMs: number): Promise<boolean> {
  const db = await getEncryptionDB();
  const tx = db.transaction([STORE_VAULT_CACHE, STORE_DEVICE_ACTIVITY], 'readwrite');
  const cacheStore = tx.objectStore(STORE_VAULT_CACHE);
  const activityStore = tx.objectStore(STORE_DEVICE_ACTIVITY);

  const [enrolledKey, activity] = await Promise.all([cacheStore.getKey(userId), activityStore.get(userId) as Promise<DeviceActivity | undefined>]);
  let expired = false;

  if (enrolledKey !== undefined) {
    const lastUsedAt = activity?.lastUsedAt;
    const dueUse = record === 'use' && (lastUsedAt === undefined || nowMs - lastUsedAt >= DAY_MS);
    const dueClock = record === 'start-clock' && lastUsedAt === undefined;

    if (isPastInactivityDelay(activity, nowMs)) {
      await Promise.all([
        cacheStore.delete(userId),
        activityStore.put({ deEnrolledAt: nowMs, inactivityDays: inactivityDays() } satisfies DeviceActivity, userId),
      ]);
      expired = true;
    } else if (dueUse || dueClock) {
      await activityStore.put(usedAt(nowMs), userId);
    }
  }

  await tx.done;

  if (expired) {
    forgetRecordedUse(userId);
    // Same aftermath as destroy-keys: nothing decrypts from memory any more, and
    // the other tabs (and their products) learn the keys are gone.
    clearSymmetricKeyCache();
    getVaultBroadcastChannel()?.postMessage({ type: BROADCAST_KEYS_DESTROYED });
  } else if (enrolledKey !== undefined) {
    recordedUses.set(userId, nowMs);
  }

  return expired;
}

/** Run by the message handler before every operation for `userId`. */
export async function recordDeviceUse(userId: string, nowMs = Date.now()): Promise<void> {
  const recorded = recordedUses.get(userId);

  if (recorded !== undefined && nowMs - recorded < DAY_MS) return;

  await checkActivity(userId, 'use', nowMs);
}

/** Forget this user's vault when it was left unused too long. True when it was. */
export async function expireIfInactive(userId: string, nowMs = Date.now()): Promise<boolean> {
  return checkActivity(userId, 'none', nowMs);
}

/** Every user of this browser, not only the one the current page is about. */
export async function expireInactiveVaults(nowMs = Date.now()): Promise<void> {
  const db = await getEncryptionDB();
  const userIds = (await db.getAllKeys(STORE_VAULT_CACHE)) as string[];

  for (const userId of userIds) {
    await checkActivity(userId, 'start-clock', nowMs);
  }
}

/** When this browser forgot the user's vault for inactivity, until it is enrolled again. */
export async function getDeEnrollment(userId: string): Promise<DeEnrollment | null> {
  const db = await getEncryptionDB();
  const activity = (await db.get(STORE_DEVICE_ACTIVITY, userId)) as DeviceActivity | undefined;

  if (activity?.deEnrolledAt === undefined || activity.inactivityDays === undefined) return null;

  return { deEnrolledAt: activity.deEnrolledAt, inactivityDays: activity.inactivityDays };
}
