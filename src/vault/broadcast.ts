import { BROADCAST_CHANNEL_NAME } from '@encryption/src/shared/constants';

/**
 * Shared BroadcastChannel instance for the vault.
 *
 * Using a single instance ensures that when the vault posts a broadcast,
 * its own listener (in index.ts) does NOT receive it — per the BroadcastChannel
 * spec, messages are delivered to every instance EXCEPT the one that sent them.
 *
 * Previously, each operation created a new instance to send, while index.ts
 * listened on a different instance, causing the same tab to receive its own
 * notifications (e.g. "keys changed from another tab" on the current tab).
 */
let sharedChannel: BroadcastChannel | null = null;

export function getVaultBroadcastChannel(): BroadcastChannel | null {
  if (sharedChannel) {
    return sharedChannel;
  }

  try {
    sharedChannel = new BroadcastChannel(BROADCAST_CHANNEL_NAME);

    return sharedChannel;
  } catch {
    return null;
  }
}

/**
 * Close and forget the shared channel. The vault never needs this at runtime
 * (the channel lives for the page), but tests must close it so an open handle
 * doesn't keep the process alive.
 */
export function closeVaultBroadcastChannel(): void {
  sharedChannel?.close();
  sharedChannel = null;
}
