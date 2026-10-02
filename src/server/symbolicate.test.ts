import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { resetSymbolicationCache, symbolicateBrowserFrames, symbolicateServerFrames } from '@encryption/src/server/symbolicate';

/**
 * A hand-written map rather than a build artifact: the test then depends on the
 * format, not on whatever the bundler happened to emit on the day it ran.
 *
 * Two mappings, both naming the same source and name:
 *   generated 1:1 -> source line 1, column 1
 *   generated 2:5 -> source line 3, column 1
 */
const MAP = {
  version: 3,
  file: 'interface-abc123.js',
  sources: ['../../../src/ui/components/Thing.tsx'],
  names: ['handleClick'],
  mappings: 'AAAAA;IAEAA',
};

const ASSET_URL = 'https://interface.encryption.example/assets/interface-abc123.js';

let workDir: string;
let previousCwd: string;

beforeAll(() => {
  previousCwd = process.cwd();
  workDir = mkdtempSync(join(tmpdir(), 'symbolicate-'));

  mkdirSync(join(workDir, 'dist/ui/assets'), { recursive: true });
  writeFileSync(join(workDir, 'dist/ui/assets/interface-abc123.js.map'), JSON.stringify(MAP));

  mkdirSync(join(workDir, 'dist/vault'), { recursive: true });
  writeFileSync(
    join(workDir, 'dist/vault/vault.js.map'),
    JSON.stringify({ ...MAP, file: 'vault.js', sources: ['../../src/vault/message-handler.ts'] })
  );

  mkdirSync(join(workDir, 'dist/server'), { recursive: true });
  writeFileSync(
    join(workDir, 'dist/server/main.mjs.map'),
    JSON.stringify({ ...MAP, file: 'main.mjs', sources: ['../../src/server/routes/health.ts'] })
  );

  process.chdir(workDir);
});

afterAll(() => {
  process.chdir(previousCwd);
  rmSync(workDir, { recursive: true, force: true });
});

beforeEach(() => {
  resetSymbolicationCache();
});

function frame(overrides: Partial<{ filename: string; lineno: number; colno: number }> = {}) {
  return { filename: ASSET_URL, function: 'o', lineno: 1, colno: 1, in_app: true, ...overrides };
}

describe('symbolicateBrowserFrames', () => {
  it('resolves a minified position to the original file, line and name', () => {
    expect(symbolicateBrowserFrames([frame()])[0]).toEqual({
      filename: 'src/ui/components/Thing.tsx',
      function: 'handleClick',
      lineno: 1,
      colno: 1,
      in_app: true,
    });
  });

  it('resolves a position that is not the first mapping', () => {
    expect(symbolicateBrowserFrames([frame({ lineno: 2, colno: 5 })])[0]).toMatchObject({
      filename: 'src/ui/components/Thing.tsx',
      lineno: 3,
    });
  });

  it('leaves a position the map does not cover alone', () => {
    // The trap this guards: asked for a line past the end of the bundle, the lookup
    // answers with the LAST mapping it holds rather than with nothing. Reporting
    // that would name a real file and a real line, both wrong, with no way to tell.
    expect(symbolicateBrowserFrames([frame({ lineno: 5000 })])[0]).toMatchObject({ filename: ASSET_URL, lineno: 5000 });
  });

  it('resolves nothing outside the interface assets directory', () => {
    for (const filename of [
      'https://interface.encryption.example/interface-abc123.js',
      'https://interface.encryption.example/assets/../../etc/passwd.js',
      'https://interface.encryption.example/assets/nested/interface-abc123.js',
      'chrome-extension://abcdef/inject.js',
      'file:///app/dist/ui/assets/interface-abc123.js',
    ]) {
      expect(symbolicateBrowserFrames([frame({ filename })])[0].filename).toBe(filename);
    }
  });

  it('passes a frame through when no build output is present', () => {
    expect(symbolicateBrowserFrames([frame({ filename: 'https://interface.encryption.example/assets/never-built.js' })])[0].filename).toBe(
      'https://interface.encryption.example/assets/never-built.js'
    );
  });

  it('reads a map once and answers from memory afterwards', () => {
    const first = symbolicateBrowserFrames([frame()])[0];

    rmSync(join(workDir, 'dist/ui/assets/interface-abc123.js.map'));

    expect(symbolicateBrowserFrames([frame()])[0]).toEqual(first);

    writeFileSync(join(workDir, 'dist/ui/assets/interface-abc123.js.map'), JSON.stringify(MAP));
  });
});

describe('vault frames', () => {
  // The vault reports a same-origin path rather than a URL, and its map lives
  // beside the vault bundle, not with the interface chunks.
  it('resolves a /vault.js position against the vault bundle map', () => {
    expect(symbolicateBrowserFrames([{ filename: '/vault.js', lineno: 1, colno: 1, in_app: true }])[0]).toEqual({
      filename: 'src/vault/message-handler.ts',
      function: 'handleClick',
      lineno: 1,
      colno: 1,
      in_app: true,
    });
  });

  it('does not let a vault-shaped path reach the interface maps, or the reverse', () => {
    const unresolved = (filename: string) => symbolicateBrowserFrames([{ filename, lineno: 1, colno: 1, in_app: true }])[0].filename;

    expect(unresolved('/assets/vault.js')).toBe('/assets/vault.js');
    expect(unresolved('/interface-abc123.js')).toBe('/interface-abc123.js');
    expect(unresolved('/assets/../vault.js')).toBe('/assets/../vault.js');
  });
});

describe('server frames', () => {
  // Built from the working directory rather than `workDir`: the two differ where the
  // temporary directory sits behind a symlink, and Node reports the resolved path.
  const bundlePath = () => join(process.cwd(), 'dist/server/main.mjs');
  const serverFrame = (filename: string, lineno = 2, colno = 5) => ({ filename, function: 'serves', lineno, colno, in_app: true });
  const mapPath = () => join(workDir, 'dist/server/main.mjs.map');
  const mapContent = JSON.stringify({ ...MAP, file: 'main.mjs', sources: ['../../src/server/routes/health.ts'] });

  afterEach(() => {
    vi.useRealTimers();
    writeFileSync(mapPath(), mapContent);
  });

  it('resolves a position in the bundle, as a file URL or a path', () => {
    for (const filename of [`file://${bundlePath()}`, bundlePath()]) {
      resetSymbolicationCache();

      expect(symbolicateServerFrames([serverFrame(filename)])[0]).toEqual({
        filename: 'src/server/routes/health.ts',
        function: 'handleClick',
        lineno: 3,
        colno: 1,
        in_app: true,
      });
    }
  });

  it('leaves every other file alone', () => {
    for (const filename of [
      'file:///elsewhere/dist/server/main.mjs',
      'dist/server/main.mjs',
      join(process.cwd(), 'dist/server/other.mjs'),
      'node:internal/process/task_queues',
      'https://interface.encryption.example/assets/interface-abc123.js',
    ]) {
      expect(symbolicateServerFrames([serverFrame(filename)])[0].filename).toBe(filename);
    }
  });

  it('keeps the map for a burst of errors, then lets it go', () => {
    vi.useFakeTimers();
    const resolved = symbolicateServerFrames([serverFrame(bundlePath())])[0];

    rmSync(mapPath());
    vi.advanceTimersByTime(59_000);
    expect(symbolicateServerFrames([serverFrame(bundlePath())])[0]).toEqual(resolved);

    vi.advanceTimersByTime(2_000);
    expect(symbolicateServerFrames([serverFrame(bundlePath())])[0].filename).toBe(bundlePath());
  });

  it('is never reachable from a browser report', () => {
    expect(symbolicateBrowserFrames([serverFrame(`file://${bundlePath()}`)])[0].filename).toBe(`file://${bundlePath()}`);
  });
});
