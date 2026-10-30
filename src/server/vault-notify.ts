/**
 * Server-push channel for the synchronized vault (SSE). When a user's vault
 * changes on one device, their OTHER devices get a content-free "your vault
 * changed" wake so they pull the update near-instantly instead of waiting for a
 * later sync trigger. The notification NEVER carries vault data — only the new
 * revision number — so it reveals nothing the server does not already hold.
 *
 * The registry is in-memory, so it only spans ONE server process: a device
 * connected to instance A is not woken by a mutation handled on instance B. A
 * multi-instance deployment must back this with a shared bus (Postgres
 * LISTEN/NOTIFY or Redis pub/sub); the client's own sync-on-open/focus is the
 * fallback that keeps things eventually-consistent regardless.
 */
import type { ServerResponse } from 'http';

const connections = new Map<string, Set<ServerResponse>>();

export function addVaultListener(userId: string, res: ServerResponse): void {
  let set = connections.get(userId);

  if (!set) {
    set = new Set();
    connections.set(userId, set);
  }

  set.add(res);
}

export function removeVaultListener(userId: string, res: ServerResponse): void {
  const set = connections.get(userId);
  if (!set) return;

  set.delete(res);
  if (set.size === 0) connections.delete(userId);
}

/** Wake this user's connected devices so they pull the new revision. */
export function notifyVaultChanged(userId: string, revision: number): void {
  const set = connections.get(userId);
  if (!set) return;

  const frame = `event: changed\ndata: ${JSON.stringify({ revision })}\n\n`;

  for (const res of set) {
    try {
      res.write(frame);
    } catch {
      set.delete(res); // dead connection: drop it
    }
  }
}
