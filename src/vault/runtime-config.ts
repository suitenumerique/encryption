import { readRuntimeConfigBlock } from '@encryption/src/shared/runtime-config';
import { type VaultRuntimeConfig, vaultRuntimeConfigSchema } from '@encryption/src/shared/schemas/runtime-config';

// Same reasoning as the interface: see src/ui/runtime-config.ts.
export const runtimeConfig: Readonly<Partial<VaultRuntimeConfig>> = readRuntimeConfigBlock(vaultRuntimeConfigSchema);
