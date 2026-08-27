/**
 * Resolves a stack reported by a BROWSER back to our TypeScript sources, here, in
 * this process, using the `.map` files that were built into the image next to the
 * bundles they describe.
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

function assetsRoot(): string {
  return resolve(process.cwd(), 'dist/ui/assets');
}

/**
 * Maps a frame's URL to the local `.map` that describes it, or null.
 *
 * Only interface assets resolve. The vault reports nothing, ever, and a frame
 * pointing anywhere else is either an extension or something we did not build.
 */
function mapPathFor(filename: string): string | null {
  let pathname: string;

  try {
    const url = new URL(filename);

    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;

    pathname = url.pathname;
  } catch {
    return null;
  }

  // The frame is attacker-influenced, so the path is constrained rather than
  // sanitized. Matched whole: the build emits `assets/` flat, so a name reached
  // through a subdirectory is not that chunk, it is a different file that happens to
  // end in the same segment, and mapping one against the other would answer with a
  // real file and a real line that have nothing to do with the failure.
  if (!/^\/assets\/[A-Za-z0-9._-]+\.js$/.test(pathname) || pathname.includes('..')) return null;

  const root = assetsRoot();
  const candidate = resolve(root, `${basename(pathname)}.map`);

  return candidate.startsWith(root + sep) ? candidate : null;
}

function loadMap(mapPath: string): SourceMap | null {
  const cached = cache.get(mapPath);

  if (cached !== undefined) return cached;

  let map: SourceMap | null = null;

  try {
    map = new SourceMap(JSON.parse(readFileSync(mapPath, 'utf-8')));
  } catch {
    // No build output, an unreadable file, or a map this Node cannot use. A frame
    // that stays minified is worth strictly more than a failed report.
    map = null;
  }

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
