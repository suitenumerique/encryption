// Shared manual mock of the emergency notification layer. Any suite that
// transitively reaches it opts in with `jest.mock('@encryption/src/server/email/emergency')`
// (no factory). Every send becomes an inert jest.fn, so:
//   - suites that just need email silent (they import a route that notifies) get
//     that for free, with no MJML render, no transport, and no evaluation of the
//     real env validator the mailer singleton runs at import;
//   - suites that assert on notifications reach into these fns directly
//     (`(sendEmergencyRecoveryReminder as jest.Mock).mockRejectedValueOnce(...)`,
//     `expect(...).toHaveBeenCalledWith(...)`).
// One place to update when a new notification is added.

export const sendEmergencyDesignated = jest.fn().mockResolvedValue(undefined);
export const sendEmergencyAccepted = jest.fn().mockResolvedValue(undefined);
export const sendEmergencyDeclined = jest.fn().mockResolvedValue(undefined);
export const sendEmergencyRecoveryRequested = jest.fn().mockResolvedValue(undefined);
export const sendEmergencyRecoveryReminder = jest.fn().mockResolvedValue(undefined);
export const sendEmergencyRecoveryApprovedGrantor = jest.fn().mockResolvedValue(undefined);
export const sendEmergencyRecoveryApprovedContact = jest.fn().mockResolvedValue(undefined);
export const sendEmergencyRecoveryRejected = jest.fn().mockResolvedValue(undefined);
export const sendEmergencyRecoveryCancelled = jest.fn().mockResolvedValue(undefined);
export const sendEmergencyVaultRecovered = jest.fn().mockResolvedValue(undefined);
export const sendEmergencyVaultRecoveredContact = jest.fn().mockResolvedValue(undefined);
export const sendEmergencyRevoked = jest.fn().mockResolvedValue(undefined);
