import { readRuntimeConfigBlock } from '@encryption/src/shared/runtime-config';
import { type VaultRuntimeConfig, vaultRuntimeConfigSchema } from '@encryption/src/shared/schemas/runtime-config';

export const runtimeConfig: Readonly<Partial<VaultRuntimeConfig>> = readRuntimeConfigBlock(vaultRuntimeConfigSchema);
