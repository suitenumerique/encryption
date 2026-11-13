import { vi } from 'vitest';

// Shared manual mock of the emergency notification layer. Any suite that
// transitively reaches it opts in with `vi.mock('@encryption/src/server/email/emergency')`
// (no factory). Every send becomes an inert vi.fn, so:
//   - suites that just need email silent (they import a route that notifies) get
//     that for free, with no MJML render, no transport, and no evaluation of the
//     real env validator the mailer singleton runs at import;
//   - suites that assert on notifications reach into these fns directly
//     (`(sendEmergencyRecoveryReminder as vi.Mock).mockRejectedValueOnce(...)`,
//     `expect(...).toHaveBeenCalledWith(...)`).
// One place to update when a new notification is added.

export const sendEmergencyDesignated = vi.fn().mockResolvedValue(undefined);
export const sendEmergencyAccepted = vi.fn().mockResolvedValue(undefined);
export const sendEmergencyDeclined = vi.fn().mockResolvedValue(undefined);
export const sendEmergencyRecoveryRequested = vi.fn().mockResolvedValue(undefined);
export const sendEmergencyRecoveryReminder = vi.fn().mockResolvedValue(undefined);
export const sendEmergencyRecoveryApprovedGrantor = vi.fn().mockResolvedValue(undefined);
export const sendEmergencyRecoveryApprovedContact = vi.fn().mockResolvedValue(undefined);
export const sendEmergencyRecoveryRejected = vi.fn().mockResolvedValue(undefined);
export const sendEmergencyRecoveryCancelled = vi.fn().mockResolvedValue(undefined);
export const sendEmergencyVaultRecovered = vi.fn().mockResolvedValue(undefined);
export const sendEmergencyVaultRecoveredContact = vi.fn().mockResolvedValue(undefined);
export const sendEmergencyRevoked = vi.fn().mockResolvedValue(undefined);
