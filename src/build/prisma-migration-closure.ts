/**
 * Build-time script listing every `node_modules` path the Prisma CLI needs, so the
 * published image can carry the migration tooling without carrying the whole tree.
 *
 * Walks the COMMITTED lockfile rather than a hand-maintained list of package names, which
 * Prisma could invalidate in any patch release. It follows `dependencies` and
 * `optionalDependencies` and deliberately NOT peer edges: a peer is the consumer's to
 * provide, and the only ones here are React (pulled in by `@prisma/studio-core`) and
 * TypeScript (an optional peer of the CLI, which loads `prisma.config.ts` through jiti
 * instead). Together they are 32 MB of code that `migrate deploy` never loads, and in a
 * single-image deployment they would otherwise sit in the long-lived server image and
 * show up in every vulnerability report.
 *
 * The result is verified against npm's own resolver: `npm query "#prisma, #prisma *"`
 * returns the same set plus exactly those six peer packages.
 */
import { readFileSync } from 'node:fs';

interface LockfileEntry {
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

const ROOT = 'node_modules/prisma';

export function collectPrismaClosure(lockfilePath = 'package-lock.json'): string[] {
  const packages = (JSON.parse(readFileSync(lockfilePath, 'utf-8')) as { packages: Record<string, LockfileEntry> }).packages;

  // Node's own lookup: walk up the nesting until the package is found, so a nested copy
  // wins over a hoisted one exactly as it would at require time.
  function resolve(from: string, name: string): string | null {
    for (let base = from; ; ) {
      const candidate = `${base ? `${base}/` : ''}node_modules/${name}`;

      if (packages[candidate]) return candidate;
      if (!base) return null;

      const cut = base.lastIndexOf('/node_modules/');

      base = cut === -1 ? '' : base.slice(0, cut);
    }
  }

  const keep = new Set<string>();
  const queue = [ROOT];

  while (queue.length > 0) {
    const path = queue.shift();

    if (!path || keep.has(path)) continue;

    keep.add(path);

    const entry = packages[path];

    if (!entry) continue;

    for (const name of Object.keys({ ...entry.dependencies, ...entry.optionalDependencies })) {
      const resolved = resolve(path, name);

      if (resolved) queue.push(resolved);
    }
  }

  return [...keep].sort();
}

const closure = collectPrismaClosure();

if (closure.length < 2) {
  // A lockfile without `prisma`, or a rename upstream, would otherwise produce an empty
  // list and an image with no migration tooling at all.
  throw new Error(`Expected the Prisma CLI and its dependencies, found ${closure.length} package(s).`);
}

process.stdout.write(`${closure.join('\n')}\n`);
