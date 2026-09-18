/**
 * Where the CLI's rows come from and where its results go: a file when the
 * operator names one (`--in`, `--out`), the standard streams otherwise.
 *
 * Files are the robust choice for a real export: it can be inspected before it is
 * processed, the command can be re-run on it, and the result file holds nothing
 * but results (a forgotten `npm run -s` prints npm's banner on stdout). Pipes stay
 * the default because they compose with psql, jq and curl for a quick look.
 */
import { createReadStream, createWriteStream } from 'node:fs';
import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';

import { type MaintenanceRow, parseRow, parseRows } from '@encryption/src/maintenance/escrow';

export function openInput(path: string | undefined): Readable {
  return path ? createReadStream(path, { encoding: 'utf8' }) : process.stdin;
}

/** A result file may hold plaintext (`decrypt`), so it is created readable by its owner only. */
export function openOutput(path: string | undefined): Writable {
  return path ? createWriteStream(path, { mode: 0o600 }) : process.stdout;
}

/**
 * One JSON object per line is parsed and yielded as it is read, so an export of
 * any size costs one row of memory. A JSON array cannot be split without a
 * streaming parser, so that shape (recognised by its leading `[`) is buffered
 * whole: fine for a REST listing, the wrong format for a large table.
 */
export async function* readRows(input: Readable): AsyncGenerator<MaintenanceRow> {
  const lines = createInterface({ input, crlfDelay: Infinity });
  let index = 0;
  let array: string[] | null = null;

  for await (const line of lines) {
    if (array) {
      array.push(line);
      continue;
    }

    if (line.trim() === '') continue;

    if (index === 0 && line.trimStart().startsWith('[')) {
      array = [line];
      continue;
    }

    let entry: unknown;

    try {
      entry = JSON.parse(line);
    } catch {
      throw new Error(`row ${index + 1}: not a JSON object on one line`);
    }

    yield parseRow(entry, index);
    index += 1;
  }

  if (array) yield* parseRows(array.join('\n'));
}

export function writeResult(output: Writable, value: unknown): void {
  output.write(`${JSON.stringify(value)}\n`);
}

export function closeOutput(output: Writable): Promise<void> {
  if (output === process.stdout) return Promise.resolve();

  return new Promise((resolve, reject) => {
    output.once('error', reject);
    output.end(resolve);
  });
}
