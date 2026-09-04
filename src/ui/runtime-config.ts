import { readRuntimeConfigBlock } from '@encryption/src/shared/runtime-config';
import { type UiRuntimeConfig, uiRuntimeConfigSchema } from '@encryption/src/shared/schemas/runtime-config';

/**
 * A module export rather than a `window` global. Not because a global cannot be
 * frozen, it can and it was, but because several modules read this at their own top
 * level: an import graph guarantees this file is evaluated first, whereas a global set
 * by the entry point would still be undefined when its imports run. It also keeps the
 * values off `window`, where a hostile library could at least read them.
 */
export const runtimeConfig: Readonly<Partial<UiRuntimeConfig>> = readRuntimeConfigBlock(uiRuntimeConfigSchema);
