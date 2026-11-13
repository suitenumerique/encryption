/**
 * Emit openapi.json from the live Fastify routes.
 *
 * openapi.json is derived from the Zod schemas the routes already validate
 * with, so the spec cannot describe anything the server does not enforce.
 * Routes without a `schema` are omitted, which is the signal that they still
 * need wiring rather than a silent gap.
 *
 * Run with `npm run api:schema:generate`. The output is committed so codegen is
 * reproducible without a database.
 */
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { createServer } from '@encryption/src/server/server';

async function main(): Promise<void> {
  const app = await createServer({ openapi: true });

  await app.ready();

  const document = app.swagger();
  const openapiPath = resolve(process.cwd(), 'openapi.json');

  writeFileSync(openapiPath, `${JSON.stringify(document, null, 2)}\n`);

  const paths = Object.keys((document as { paths?: Record<string, unknown> }).paths ?? {});

  console.log(`Wrote ${openapiPath} (${paths.length} paths)`);
  for (const path of paths.sort()) {
    console.log(`  ${path}`);
  }

  await app.close();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
