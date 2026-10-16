// Pure decision logic for the emergency-access (trusted contacts) screens,
// kept free of React/Cunningham imports so it can be unit-tested directly.
import type { EmergencyDesignateBody, EmergencyRearmBody } from '@encryption/src/shared/schemas/emergency-access';

export const WAIT_TIME_PRESETS = [7, 15, 30] as const;
export const MIN_WAIT_DAYS = 1;
export const MAX_WAIT_DAYS = 90;

/**
 * Parse the custom wait-time input: a whole number of days within the server
 * bounds (1..90), or null for anything else (empty, fractional, out of range).
 */
export function parseWaitDays(raw: string): number | null {
  const trimmed = raw.trim();

  if (!/^\d+$/.test(trimmed)) return null;

  const days = Number(trimmed);

  return days >= MIN_WAIT_DAYS && days <= MAX_WAIT_DAYS ? days : null;
}

// The status fields the phase/rearm decisions need, shared by the trusted
// (grantor-side) and granted (contact-side) wire entries.
interface ApprovalFields {
  status: 'invited' | 'confirmed' | 'recoveryRequested' | 'recoveryApproved';
  deadline_millis: number | null;
}

export type EmergencyPhase = 'invited' | 'confirmed' | 'requested' | 'approved';

/**
 * The phase a relationship is EFFECTIVELY in at `nowMillis`. The server keeps
 * `recoveryRequested` in the row even once the wait has elapsed (approval is
 * re-derived from the deadline arithmetic on every sensitive call), so a
 * request whose deadline has passed must read as approved here too.
 */
export function emergencyPhase(entry: ApprovalFields, nowMillis: number): EmergencyPhase {
  if (entry.status === 'recoveryApproved') return 'approved';
  if (entry.status === 'recoveryRequested') {
    return entry.deadline_millis !== null && entry.deadline_millis <= nowMillis ? 'approved' : 'requested';
  }

  return entry.status;
}

export interface RearmRow {
  emergencyAccessId: string;
  granteeUserId: string;
  granteeEmail: string;
  waitTimeDays: number;
}

/**
 * The relationships a keyring rewrite MUST burn + re-arm: the ones on the
 * ACTIVE vault whose recovery approval currently holds (mirrors the server's
 * `emergencyApprovalHolds` + same-vault filter, which rejects the PUT with
 * `emergency_rearm_required` unless every one of them is covered). Rows bound
 * to a previous (disabled) vault never gate the active keyring.
 */
export function grantedRearmRows(
  contacts: Array<ApprovalFields & { id: string; grantee_user_id: string; grantee_email: string; wait_time_days: number; vault_active?: boolean }>,
  nowMillis: number
): RearmRow[] {
  return contacts
    .filter((contact) => contact.vault_active !== false && emergencyPhase(contact, nowMillis) === 'approved')
    .map((contact) => ({
      emergencyAccessId: contact.id,
      granteeUserId: contact.grantee_user_id,
      granteeEmail: contact.grantee_email,
      waitTimeDays: contact.wait_time_days,
    }));
}

/**
 * The standalone re-arm POST body is the designation body minus the two
 * relationship fields (they are fixed by the row being re-armed). Field order
 * is preserved so the JSON sent matches the JSON signed.
 */
export function rearmBodyFromDesignation(body: EmergencyDesignateBody): EmergencyRearmBody {
  const { grantee_user_id: _granteeUserId, wait_time_days: _waitTimeDays, ...rearm } = body;

  return rearm;
}

export interface Countdown {
  expired: boolean;
  days: number;
  hours: number;
  minutes: number;
}

/** Time left until `deadlineMillis`, floored to whole units for display. */
export function countdownTo(deadlineMillis: number, nowMillis: number): Countdown {
  const remaining = deadlineMillis - nowMillis;

  if (remaining <= 0) return { expired: true, days: 0, hours: 0, minutes: 0 };

  const minutesTotal = Math.floor(remaining / 60_000);

  return {
    expired: false,
    days: Math.floor(minutesTotal / (24 * 60)),
    hours: Math.floor(minutesTotal / 60) % 24,
    minutes: minutesTotal % 60,
  };
}

/**
 * Thrown by the keyring-commit flow when some granted contacts are no longer
 * TOFU-trusted, so their mandatory re-arm cannot be built. The caller offers
 * to revoke exactly these relationships and retry.
 */
export class UntrustedRearmError extends Error {
  readonly contacts: Array<{ id: string; email: string }>;

  constructor(contacts: Array<{ id: string; email: string }>) {
    super('Some granted contacts are no longer trusted; their escrow cannot be re-armed.');
    this.name = 'UntrustedRearmError';
    this.contacts = contacts;
  }
}
