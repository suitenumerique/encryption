import { defineConfig } from '@hey-api/openapi-ts';

/**
 * Generates the typed API surface from openapi.json (itself emitted from the
 * routes' Zod schemas by `npm run api:schema:generate`). Everything downstream, the UI
 * client, the Storybook mocks and the route tests, consumes this one output, so
 * a request or response shape can only drift by changing the server schema.
 *
 * Regenerate with `npm run api:client:generate` (or `npm run api:schema:sync` to
 * redo both steps: emit the spec, then the client).
 */
export default defineConfig({
  input: './openapi.json',
  output: {
    path: './src/ui/api/generated',
    postProcess: ['prettier'],
  },
  plugins: ['@hey-api/client-fetch', '@hey-api/typescript', '@hey-api/sdk', 'msw'],
});
