import { VaultClient } from '@encryption/src/client/vault-client';
import { VaultError, VaultErrorCode, isVaultError } from '@encryption/src/shared/vault-error';

export { VaultClient, VaultError, VaultErrorCode, isVaultError };
// RegisteredUser + RecipientLabel are exported at the ENTRY (not just re-exported
// from vault-client) so the rolled-up client.d.ts keeps them exported and the
// `export as namespace EncryptionClient` surface carries them — integrating
// products reference them by name off the vendored declaration.
export type { AuthContext, EncryptionClientEventMap, EncryptionClientOptions, RecipientLabel, RegisteredUser } from '@encryption/src/client/vault-client';
