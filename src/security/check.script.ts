/**
 * Entry point for the supply chain checks. One command per concern:
 *
 *   lockfile         assert every dependency is registry-resolved and hash-verified
 *   actions          assert every GitHub Action is pinned to a commit SHA
 *
 * Each command exits non-zero on a violation so it can be a CI gate directly.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { checkWorkflow } from '@encryption/src/security/actions-pinning';
import { type Lockfile, checkLockfile } from '@encryption/src/security/lockfile-policy';

const root = process.cwd();

function readJson<T>(relativePath: string): T {
  return JSON.parse(readFileSync(resolve(root, relativePath), 'utf8')) as T;
}

function fail(message: string, details: string[]): never {
  console.error(`\n${message}\n`);
  for (const detail of details) console.error(`  ${detail}`);
  console.error('');
  process.exit(1);
}

function commandLockfile(): void {
  const violations = checkLockfile(readJson<Lockfile>('package-lock.json'));

  if (violations.length > 0) {
    fail(
      'Lockfile policy check failed. Every dependency must come from the public registry with an integrity hash.',
      violations.slice(0, 50).map((violation) => `[${violation.kind}] ${violation.path || '(root)'}: ${violation.detail}`)
    );
  }

  console.log('Lockfile policy: every entry is registry-resolved and hash-verified.');
}

async function commandActions(): Promise<void> {
  const { readdir } = await import('node:fs/promises');
  const workflowsDir = resolve(root, '.github/workflows');
  const files = (await readdir(workflowsDir)).filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'));

  const violations = files.flatMap((name) => checkWorkflow(name, readFileSync(resolve(workflowsDir, name), 'utf8')));

  if (violations.length > 0) {
    fail(
      'GitHub Actions policy check failed.',
      violations.map((violation) => `[${violation.kind}] ${violation.file}:${violation.line} ${violation.detail}`)
    );
  }

  console.log(`${files.length} workflows checked; every action is pinned to a commit SHA.`);
}

const commands: Record<string, () => void | Promise<void>> = {
  lockfile: commandLockfile,
  actions: commandActions,
};

const requested = process.argv[2];
const command = requested ? commands[requested] : undefined;

if (!command) {
  console.error(`Usage: tsx src/security/check.script.ts <${Object.keys(commands).join('|')}>`);
  process.exit(1);
}

await command();
