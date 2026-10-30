import type { FastifyInstance } from 'fastify';

import { createClient, createConfig } from '@encryption/src/ui/api/generated/client';
import type { ClientOptions } from '@encryption/src/ui/api/generated/types.gen';

/**
 * A WHATWG `fetch` backed by `app.inject()`: no port, no socket, but the
 * complete Fastify lifecycle (hooks, schema validation, serialization). Note
 * `inject()` implicitly calls `app.ready()`, so plugins are fully booted.
 */
export function injectFetch(app: FastifyInstance): typeof fetch {
  return async (input, init) => {
    const request = new Request(input as RequestInfo, init);
    const url = new URL(request.url);
    const hasBody = request.method !== 'GET' && request.method !== 'HEAD';

    const response = await app.inject({
      method: request.method as 'GET',
      url: url.pathname + url.search,
      headers: Object.fromEntries(request.headers),
      payload: hasBody ? await request.text() : undefined,
    });

    // rawPayload is a Node Buffer; take its bytes so the WHATWG Response body
    // accepts it (a Buffer is not a BodyInit).
    return new Response(new Uint8Array(response.rawPayload), {
      status: response.statusCode,
      headers: response.headers as Record<string, string>,
    });
  };
}

/**
 * The generated SDK pointed at an in-process app. Route tests call the same
 * functions the interface calls, so a test cannot send a body shape or assert a
 * response shape that the OpenAPI document (and therefore the server's Zod
 * schemas) does not agree with.
 *
 * `throwOnError: false` keeps error responses inspectable as `{ error, response }`
 * rather than exceptions, since most route tests assert on failure codes.
 */
export function createTestApiClient(app: FastifyInstance) {
  return createClient(
    createConfig<ClientOptions>({
      baseUrl: 'http://test.local',
      fetch: injectFetch(app),
      throwOnError: false,
    })
  );
}
