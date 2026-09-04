import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

// Directories whose code is bundled for a browser. The server is deliberately absent:
// it has no CSP, so it keeps the compiled fast path.
const BROWSER_DIRS = ['src/client', 'src/crypto', 'src/shared', 'src/ui', 'src/vault'];

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);

    if (statSync(path).isDirectory()) return walk(path);

    return /\.tsx?$/.test(path) && !/\.test\.tsx?$/.test(path) ? [path] : [];
  });
}

describe('zod-jitless', () => {
  // Skipping the import would not fail any assertion or break any behaviour: it would
  // only bring back one CSP violation report per page load, which is exactly the kind
  // of regression nobody notices. Hence a test rather than a comment.
  it('is imported by every browser-bundled module that builds a schema', () => {
    const root = resolve(__dirname, '../..');
    const offenders = BROWSER_DIRS.flatMap(walk.bind(null))
      .map((path) => join(root, path))
      .filter((path) => !path.endsWith('/shared/zod-jitless.ts'))
      .filter((path) => {
        const source = readFileSync(path, 'utf-8');

        // A `import type { ... } from 'zod'` builds nothing, so it needs nothing.
        const buildsSchemas = /^import (?!type )[^;]*from 'zod';/m.test(source);

        return buildsSchemas && !source.includes("'@encryption/src/shared/zod-jitless'");
      })
      .map((path) => path.slice(root.length + 1));

    expect(offenders).toEqual([]);
  });
});
