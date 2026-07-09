import { VaultClient } from '@encryption/src/client/vault-client';
import { VaultError, VaultErrorCode, isVaultError } from '@encryption/src/shared/vault-error';

export { VaultClient, VaultError, VaultErrorCode, isVaultError };
export type { AuthContext, EncryptionClientEventMap, EncryptionClientOptions } from '@encryption/src/client/vault-client';
