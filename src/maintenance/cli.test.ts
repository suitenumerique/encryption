/**
 * The CLI as an operator runs it: a real process, stdin rows, stdout results.
 * The crypto is proven in escrow.test.ts; this checks the command surface
 * (key file handling, exit codes, stream format) does not drift.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import { encryptContent, generateSymmetricKey, parseMaintenancePublicKey, uint8ToBase64, wrapKeyForMaintenance } from '@encryption/src/crypto';

const CLI = resolve(import.meta.dirname, 'cli.ts');

function run(args: string[], input?: string): { stdout: string; stderr: string; status: number } {
  try {
    const stdout = execFileSync('npx', ['tsx', CLI, ...args], { encoding: 'utf8', input, stdio: ['pipe', 'pipe', 'pipe'] });

    return { stdout, stderr: '', status: 0 };
  } catch (error) {
    const failure = error as { stdout: string; stderr: string; status: number };

    return { stdout: failure.stdout, stderr: failure.stderr, status: failure.status };
  }
}

const lines = (stdout: string): unknown[] =>
  stdout
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as unknown);

describe('maintenance CLI', { timeout: 120_000 }, () => {
  const dir = mkdtempSync(resolve(tmpdir(), 'maintenance-'));
  const keyFile = resolve(dir, 'maintenance.json');

  it('keygen writes a private key file and prints the public key, then refuses to overwrite', () => {
    const first = run(['keygen', '--out', keyFile]);

    expect(first.status).toBe(0);
    expect(existsSync(keyFile)).toBe(true);
    expect(statSync(keyFile).mode & 0o777).toBe(0o600);

    const publicKey = first.stdout.trim();
    expect(parseMaintenancePublicKey(publicKey).length).toBe(1216);
    expect(run(['public-key', '--key', keyFile]).stdout.trim()).toBe(publicKey);
    expect(first.stdout).not.toContain((JSON.parse(readFileSync(keyFile, 'utf8')) as { secretKey: string }).secretKey);

    expect(run(['keygen', '--out', keyFile]).status).not.toBe(0);
  });

  it('check, decrypt and rewrap stream one JSON result per row and exit non-zero on a bad row', async () => {
    const publicKey = parseMaintenancePublicKey(run(['public-key', '--key', keyFile]).stdout.trim());
    const key = await generateSymmetricKey();
    const rows = [
      {
        id: 'doc-ok',
        maintenanceKey: uint8ToBase64(await wrapKeyForMaintenance(key, publicKey)),
        encryptedContent: uint8ToBase64(await encryptContent(new TextEncoder().encode('bonjour'), key)),
        recipients: {},
      },
      { id: 'doc-bad', maintenanceKey: uint8ToBase64(new Uint8Array(8)) },
    ];
    const ndjson = rows.map((row) => JSON.stringify(row)).join('\n');

    const check = run(['check', '--key', keyFile], ndjson);
    expect(check.status).toBe(1);
    expect(lines(check.stdout)).toEqual([
      { id: 'doc-ok', ok: true },
      { id: 'doc-bad', ok: false, error: expect.any(String) },
    ]);

    const decrypt = run(['decrypt', '--key', keyFile, '--utf8'], JSON.stringify([rows[0]]));
    expect(decrypt.status).toBe(0);
    expect(lines(decrypt.stdout)).toEqual([{ id: 'doc-ok', plaintext: 'bonjour' }]);

    const rewrap = run(['rewrap', '--key', keyFile, '--rotate-key'], ndjson);
    expect(rewrap.status).toBe(1);
    expect(rewrap.stderr).toContain('1 of 2 row(s) succeeded');
    const [rotated, failed] = lines(rewrap.stdout) as [Record<string, unknown>, Record<string, unknown>];
    expect(rotated).toEqual({ id: 'doc-ok', encryptedKeys: {}, maintenanceKey: expect.any(String), encryptedContent: expect.any(String) });
    expect(failed).toEqual({ id: 'doc-bad', error: expect.any(String) });

    // The rotated row is a complete replacement that the same key file still opens.
    const again = run(['decrypt', '--key', keyFile, '--utf8'], JSON.stringify({ id: 'doc-ok', ...rotated }));
    expect(lines(again.stdout)).toEqual([{ id: 'doc-ok', plaintext: 'bonjour' }]);
  });

  it('reads rows from --in and writes results to --out, leaving stdout empty and the result file private', async () => {
    const publicKey = parseMaintenancePublicKey(run(['public-key', '--key', keyFile]).stdout.trim());
    const key = await generateSymmetricKey();
    const rows = await Promise.all(
      ['un', 'deux', 'trois'].map(async (content, index) => ({
        id: `doc-${index + 1}`,
        maintenanceKey: uint8ToBase64(await wrapKeyForMaintenance(key, publicKey)),
        encryptedContent: uint8ToBase64(await encryptContent(new TextEncoder().encode(content), key)),
      }))
    );
    const expected = [
      { id: 'doc-1', plaintext: 'un' },
      { id: 'doc-2', plaintext: 'deux' },
      { id: 'doc-3', plaintext: 'trois' },
    ];

    // One JSON object per line, with a blank line and CRLF endings as an export tool may leave them.
    const ndjsonFile = resolve(dir, 'rows.ndjson');
    const resultFile = resolve(dir, 'results.ndjson');
    writeFileSync(ndjsonFile, `${rows.map((row) => JSON.stringify(row)).join('\r\n')}\r\n\r\n`);

    const fromFile = run(['decrypt', '--key', keyFile, '--utf8', '--in', ndjsonFile, '--out', resultFile]);
    expect(fromFile.status).toBe(0);
    expect(fromFile.stdout).toBe('');
    expect(statSync(resultFile).mode & 0o777).toBe(0o600);
    expect(lines(readFileSync(resultFile, 'utf8'))).toEqual(expected);

    // A pretty-printed JSON array (a REST listing saved to disk) is accepted too.
    const arrayFile = resolve(dir, 'rows.json');
    writeFileSync(arrayFile, JSON.stringify(rows, null, 2));
    expect(lines(run(['decrypt', '--key', keyFile, '--utf8', '--in', arrayFile]).stdout)).toEqual(expected);

    // A line that is not JSON stops the run with its position, after the rows before it were processed.
    const brokenFile = resolve(dir, 'broken.ndjson');
    writeFileSync(brokenFile, `${JSON.stringify(rows[0])}\nnot json\n`);
    const broken = run(['check', '--key', keyFile, '--in', brokenFile]);
    expect(broken.status).toBe(1);
    expect(broken.stderr).toContain('row 2');
    expect(lines(broken.stdout)).toEqual([{ id: 'doc-1', ok: true }]);
  });
});
