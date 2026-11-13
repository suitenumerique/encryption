import { vi } from 'vitest';

// Inert sends for suites that opt in with `vi.mock('@encryption/src/server/email/vault-retention')`;
// see the emergency mock next to this file.
export const sendVaultPurgeWarning = vi.fn().mockResolvedValue(undefined);
export const sendVaultPurged = vi.fn().mockResolvedValue(undefined);
