import { createMswHandlers } from '@encryption/src/ui/api/generated/msw.gen';

/**
 * A safety net, NOT a data source.
 *
 * Installed as the worker's initial handlers in .storybook/preview.tsx, this
 * answers every operation in the OpenAPI document with 501 Not Implemented, so
 * no story can silently reach the network. Initial handlers sit behind the ones
 * a story declares (the addon prepends those at runtime), which is what keeps
 * the net under every story; a `parameters.msw.handlers` array would instead be
 * replaced outright by a story's own array. It deliberately supplies no happy-path data: a story that needs a
 * response declares it itself, with the generated `handle*` factory, in its own
 * `parameters.msw.handlers`.
 *
 * That is the point. Shared happy-path defaults would make each story depend on
 * a distant file: the story would stop describing the state it demonstrates, and
 * editing the defaults would quietly change many stories at once with nothing
 * local to review. A 501 fails loudly and locally instead, naming the endpoint
 * the story forgot to mock.
 *
 * `all()` covers new routes automatically once `npm run api:schema:sync` runs,
 * so the net never develops holes.
 */
export const defaultHandlers = [...createMswHandlers().all()];
