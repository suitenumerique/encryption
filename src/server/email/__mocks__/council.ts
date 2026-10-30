import { vi } from 'vitest';

// Shared manual mock of the recovery council notifications, used like the
// emergency one: `vi.mock('@encryption/src/server/email/council')` with no factory.

export const sendCouncilRecoveryRequested = vi.fn().mockResolvedValue(undefined);
export const sendCouncilRecoveryToApprove = vi.fn().mockResolvedValue(undefined);
export const sendCouncilRecoveryMeeting = vi.fn().mockResolvedValue(undefined);
export const sendCouncilRecoveryCompleted = vi.fn().mockResolvedValue(undefined);
export const sendCouncilRecoveryCompletedCustodian = vi.fn().mockResolvedValue(undefined);
export const sendCouncilRecoveryAborted = vi.fn().mockResolvedValue(undefined);
export const sendCouncilRosterToSign = vi.fn().mockResolvedValue(undefined);
export const sendCouncilLeft = vi.fn().mockResolvedValue(undefined);
