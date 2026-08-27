import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { resetSymbolicationCache, symbolicateBrowserFrames } from '@encryption/src/server/symbolicate';

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
