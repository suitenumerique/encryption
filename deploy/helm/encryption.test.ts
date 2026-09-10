import { execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseAllDocuments } from 'yaml';

import { envSchema } from '@encryption/src/server/env-schema';

/**
 * Rendered by the real Helm binary (Go templates cannot be reproduced in JavaScript),
 * then checked for what a render alone cannot say. The shape of the output is the
 * committed snapshot, reviewed on every change; the assertions below are only the
 * invariants that must hold in every configuration. The one that matters most reads
 * `src/server/env-schema.ts`: the chart cannot fall behind the server without failing.
 *
 * Needs `helm` on the PATH (and `kubeconform` in CI): `brew install helm kubeconform`.
 * `deploy/helm/smoke-k3d.sh` is the other layer, a real install in a local cluster.
 */

const CHART = resolve(import.meta.dirname, 'encryption');
const FULL_VALUES = resolve(CHART, 'ci/full-values.yaml');
const EXISTING_SECRETS_VALUES = resolve(CHART, 'ci/existing-secrets-values.yaml');

interface EnvEntry {
  name: string;
  value?: string;
  valueFrom?: { secretKeyRef?: { name: string; key: string } };
}

interface Manifest {
  kind: string;
  spec?: { template?: { spec: { containers: { env: EnvEntry[] }[] } } };
}

function run(command: string, args: string[], input?: string): string {
  try {
    return execFileSync(command, args, { encoding: 'utf8', input, stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (error) {
    const failure = error as { stderr?: string; stdout?: string; message: string };

    throw new Error(`${command} ${args.join(' ')} failed:\n${failure.stderr || failure.stdout || failure.message}`, { cause: error });
  }
}

function isInstalled(command: string, versionArgs: string[]): boolean {
  try {
    execFileSync(command, versionArgs, { stdio: 'ignore' });

    return true;
  } catch {
    return false;
  }
}

function render(values: string, set: string[] = []): { text: string; docs: Manifest[] } {
  const text = run('helm', ['template', 'enc', CHART, '--namespace', 'encryption', '--values', values, ...set.flatMap((entry) => ['--set', entry])]);
  const docs = parseAllDocuments(text)
    .map((document) => document.toJS() as Manifest | null)
    .filter((document): document is Manifest => document !== null && typeof document === 'object');

  return { text, docs };
}

function renderError(values: string, set: string[]): string {
  try {
    render(values, set);
  } catch (error) {
    return (error as Error).message;
  }

  throw new Error('expected the render to fail');
}

function serverEnv(docs: Manifest[]): Map<string, EnvEntry> {
  const deployment = docs.find((document) => document.kind === 'Deployment');
  const container = deployment?.spec?.template?.spec.containers[0];

  if (!container) throw new Error('no Deployment in the render');

  return new Map(container.env.map((entry) => [entry.name, entry]));
}

// Variables the server refuses to boot without: those the schema rejects when absent.
const REQUIRED_VARIABLES = Object.entries(envSchema.shape)
  .filter(([, schema]) => !schema.safeParse(undefined).success)
  .map(([name]) => name);
const KNOWN_VARIABLES = new Set([...Object.keys(envSchema.shape), 'NODE_ENV']);
const SECRET_VARIABLE = /^(?:DATABASE_URL|SENTRY_DSN|MAILER_.*_(?:USER|PASSWORD))$/;

// Renders happen while the suites are collected, so the guard has to run at import time.
if (!isInstalled('helm', ['version', '--short'])) {
  throw new Error('The chart tests need the helm binary on the PATH (brew install helm, or https://helm.sh/docs/intro/install/)');
}

describe('the chart', () => {
  const full = render(FULL_VALUES);
  const minimal = render(EXISTING_SECRETS_VALUES);

  it('lints strictly and validates against the Kubernetes API schemas', () => {
    for (const values of [FULL_VALUES, EXISTING_SECRETS_VALUES]) {
      expect(run('helm', ['lint', '--strict', CHART, '--values', values])).toContain('0 chart(s) failed');
    }

    if (!isInstalled('kubeconform', ['-v'])) {
      if (process.env.CI) throw new Error('kubeconform is required in CI');
      console.warn('kubeconform is not installed, skipping the API schema validation (brew install kubeconform)');

      return;
    }

    const cache = mkdtempSync(resolve(tmpdir(), 'kubeconform-'));

    for (const { text } of [full, minimal]) {
      const summary = run('kubeconform', ['-strict', '-summary', '-kubernetes-version', '1.30.0', '-cache', cache], text);

      expect(summary).toMatch(/Invalid: 0/);
      expect(summary).toMatch(/Errors: 0/);
    }
  });

  it('renders the same objects as last time (review the snapshot diff on any change)', () => {
    expect(full.text).toMatchSnapshot();
  });

  it('passes every variable the server requires, and nothing the server does not read', () => {
    for (const env of [serverEnv(full.docs), serverEnv(minimal.docs)]) {
      for (const name of REQUIRED_VARIABLES) {
        expect(env.has(name), `${name} is required by src/server/env-schema.ts`).toBe(true);
      }

      for (const name of env.keys()) {
        expect(KNOWN_VARIABLES.has(name), `${name} is not a variable the server reads`).toBe(true);
      }
    }
  });

  it('never puts a secret in a plain env value', () => {
    for (const env of [serverEnv(full.docs), serverEnv(minimal.docs)]) {
      for (const [name, entry] of env) {
        if (!SECRET_VARIABLE.test(name)) continue;

        expect(entry.value, `${name} must come from a Secret`).toBeUndefined();
        expect(entry.valueFrom?.secretKeyRef, name).toBeDefined();
      }
    }

    expect(
      minimal.docs.some((document) => document.kind === 'Secret'),
      'existing secrets only: no Secret of its own'
    ).toBe(false);
  });

  it('fails early, naming the value, instead of rendering a pod that cannot boot', () => {
    expect(renderError(FULL_VALUES, ['extraEnvs=1'])).toMatch(/extraEnvs.*not allowed|not allowed.*extraEnvs/);
    expect(renderError(FULL_VALUES, ['config.oidc.issuer=http://insecure.example.org'])).toMatch(/issuer/);
    expect(renderError(FULL_VALUES, ['hosts.vault='])).toContain('hosts.vault is required');
    expect(renderError(FULL_VALUES, ['database.url='])).toContain('database.url or database.existingSecret.name is required');
    expect(renderError(EXISTING_SECRETS_VALUES, ['image.digest='])).toContain('image.tag or image.digest is required');
  });

  it('renders nothing for what is off', () => {
    const { docs } = render(EXISTING_SECRETS_VALUES, ['database.migration.enabled=false', 'sentry.enabled=false', 'replicaCount=1']);
    const kinds = new Set(docs.map((document) => document.kind));

    expect(kinds.has('Job')).toBe(false);
    expect(kinds.has('Ingress')).toBe(false);
    expect(kinds.has('NetworkPolicy')).toBe(false);
    expect(kinds.has('PodDisruptionBudget')).toBe(false);
    expect([...serverEnv(docs).keys()].filter((name) => name.startsWith('SENTRY_'))).toEqual([]);
  });
});
