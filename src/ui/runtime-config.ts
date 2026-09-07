import { readRuntimeConfigBlock } from '@encryption/src/shared/runtime-config';
import { type UiRuntimeConfig, uiRuntimeConfigSchema } from '@encryption/src/shared/schemas/runtime-config';

export const runtimeConfig: Readonly<Partial<UiRuntimeConfig>> = readRuntimeConfigBlock(uiRuntimeConfigSchema);
