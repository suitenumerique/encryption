/**
 * Translates the server bundle positions found in a stack or in log lines back to
 * the TypeScript sources. The running server does not hold its source map (see
 * src/server/symbolicate.ts), so its logs say `main.mjs:312045:12`; this answers
 * `src/server/routes/health.ts:42:5` from the map built next to the bundle.
 *
 *   npm run stack:resolve -- 'main.mjs:312045:12'
 *   kubectl logs ... | npm run --silent stack:resolve
 *   npm run stack:resolve -- --map ./main.mjs.map < stack.txt
 *
 * The map must come from the same build as the bundle that produced the positions:
 * the deployed image carries it at /app/dist/server/main.mjs.map.
 */
import { readFileSync } from 'node:fs';
import { SourceMap } from 'node:module';
import { parseArgs } from 'node:util';

import { symbolicateFramesWith } from '@encryption/src/server/symbolicate';

const POSITION_PATTERN = /(?:file:\/\/)?[^\s()]*main\.mjs:(\d+):(\d+)/g;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: { map: { type: 'string', default: 'dist/server/main.mjs.map' } },
});

const map = new SourceMap(JSON.parse(readFileSync(values.map, 'utf-8')));
const input = positionals.length > 0 ? positionals.join('\n') : readFileSync(0, 'utf-8');

const output = input.replace(POSITION_PATTERN, (position: string, line: string, column: string) => {
  const [frame] = symbolicateFramesWith([{ filename: 'main.mjs', lineno: Number(line), colno: Number(column), in_app: true }], map);

  return frame.filename === 'main.mjs' ? position : `${frame.filename}:${frame.lineno}:${frame.colno}`;
});

process.stdout.write(output.endsWith('\n') ? output : `${output}\n`);
