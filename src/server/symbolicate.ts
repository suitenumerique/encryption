/**
 * Resolves a stack reported by a BROWSER back to our TypeScript sources, here, in
 * this process, using the `.map` files that were built into the image next to the
 * bundles they describe.
 *
 * The browser plays no part in this. It sends its stack as text, pointing at
 * positions in the minified bundle it ran (`/assets/interface-abc.js:1:5000`), and
 * this module opens `dist/ui/assets/interface-abc.js.map` from the local disk to
 * translate each position into `src/ui/....tsx:line:col`. The map is never served
 * and the bundle carries no `sourceMappingURL` comment (Vite's `hidden` mode), so
 * no browser ever asks for it.
 *
 * The usual arrangement is the opposite one: a build pipeline uploads source maps to
 * an error collector, which un-minifies incoming events on its side. That does not
 * fit this project. The image published from this repository is a public artifact
 * that many different organizations deploy against their own collector, so a CI job
 * uploading maps would be uploading them to OUR collector, which is the one place
 * they are useless. Resolving here instead means a deployment needs nothing beyond
 * `SENTRY_DSN`: no auth token, no release matching, no upload step, and no
 * requirement that the collector even supports source maps.
 *
 * The map never leaves the container either way. What is sent is the result, a file
 * name and a line, which is what a stack was going to end up saying anyway.
 *
 * The SERVER side needs none of this: `--enable-source-maps` (see the Dockerfile)
 * has Node resolve its own stacks before they ever reach an error handler, which
 * fixes the logs at the same time.
 */
import { readFileSync } from 'node:fs';
import { SourceMap } from 'node:module';
import { basename, resolve, sep } from 'node:path';

import type { SentryFrame } from '@encryption/src/server/monitoring';

/**
 * The interface emits a handful of chunks, so this only ever holds a few entries.
 * The cap is there because the frames come from a public endpoint: it bounds what an
 * arbitrary POST can make this process keep in memory, however many distinct file
 * names it invents. A cached `null` counts too, so a miss is not retried on disk.
 */
const MAX_CACHED_MAPS = 8;

const cache = new Map<string, SourceMap | null>();

/**
 * The bundles a reported frame may point at, each with the directory holding its
 * map. The path is matched whole: the builds emit these directories flat, so a name
 * reached through a subdirectory is not that chunk, it is a different file that
 * happens to end in the same segment, and mapping one against the other would
 * answer with a real file and a real line that have nothing to do with the failure.
 */
const BUNDLES: { pattern: RegExp; mapDir: string }[] = [
  { pattern: /^\/assets\/[A-Za-z0-9._-]+\.js$/, mapDir: 'dist/ui/assets' }, // interface chunks
  { pattern: /^\/(?:vault|sw)\.js$/, mapDir: 'dist/vault' }, // the vault and its Service Worker
];

/**
 * Maps a frame's location to the local `.map` that describes it, or null. Reports
 * carry same-origin paths; a full URL is accepted for the server's own frames. A
 * frame pointing anywhere else is either an extension or something we did not build.
 */
function mapPathFor(filename: string): string | null {
  let pathname: string;

  if (filename.startsWith('/')) {
    pathname = filename;
  } else {
    try {
      const url = new URL(filename);

      if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;

      pathname = url.pathname;
    } catch {
      return null;
    }
  }

  // The frame is attacker-influenced, so the path is constrained rather than sanitized.
  if (pathname.includes('..')) return null;

  const bundle = BUNDLES.find((b) => b.pattern.test(pathname));

  if (!bundle) return null;

  const root = resolve(process.cwd(), bundle.mapDir);
  const candidate = resolve(root, `${basename(pathname)}.map`);

  return candidate.startsWith(root + sep) ? candidate : null;
}

function readMap(mapPath: string): SourceMap | null {
  try {
    return new SourceMap(JSON.parse(readFileSync(mapPath, 'utf-8')));
  } catch {
    // No build output, an unreadable file, or a map this Node cannot use. A frame
    // that stays minified is worth strictly more than a failed report.
    return null;
  }
}

function loadMap(mapPath: string): SourceMap | null {
  const cached = cache.get(mapPath);

  if (cached !== undefined) return cached;

  const map = readMap(mapPath);

  if (cache.size >= MAX_CACHED_MAPS) cache.clear();

  cache.set(mapPath, map);

  return map;
}

/** Source paths are relative to the output directory: `../../../src/ui/x.tsx`. */
function normalizeSource(source: string): string {
  return source.replace(/^(?:\.\.?\/)+/, '');
}

function symbolicateFrame(frame: SentryFrame): SentryFrame {
  if (frame.filename === undefined || frame.lineno === undefined || frame.colno === undefined) return frame;

  const mapPath = mapPathFor(frame.filename);

  if (mapPath === null) return frame;

  const map = loadMap(mapPath);

  if (map === null) return frame;

  // Both lookups take the position in the generated file; `findEntry` is 0-based and
  // `findOrigin` is 1-based. `findEntry` is here to VALIDATE: it answers with the
  // nearest mapping at or before the position asked for and reports it whether or
  // not the position was inside the file at all, so a line number past the end of
  // the bundle comes back as the bundle's last mapping, stated with full confidence.
  // Requiring the mapping to sit on the line we asked about is what rejects that.
  const entry = map.findEntry(frame.lineno - 1, frame.colno - 1);

  if (!('originalSource' in entry) || entry.generatedLine !== frame.lineno - 1) return frame;

  const origin = map.findOrigin(frame.lineno, frame.colno);

  if (!('fileName' in origin)) return frame;

  const filename = normalizeSource(origin.fileName);

  return {
    ...frame,
    filename,
    lineno: origin.lineNumber,
    colno: origin.columnNumber,
    // The minified name is a single letter; the original one is worth having.
    function: origin.name !== undefined && origin.name !== '' ? origin.name : frame.function,
    in_app: filename.startsWith('src/'),
  };
}

/** Frames that resolve are replaced; the rest are passed through untouched. */
export function symbolicateBrowserFrames(frames: SentryFrame[]): SentryFrame[] {
  return frames.map(symbolicateFrame);
}

/** Lets a test start from a known state; the cache is otherwise process-lifetime. */
export function resetSymbolicationCache(): void {
  cache.clear();
}
