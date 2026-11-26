import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// The version CI installs, so a local run is compared with what CI renders with.
const SETUP_HELM_ACTION = resolve(import.meta.dirname, '../../.github/actions/setup-helm/action.yml');

function parseVersion(text: string): number[] | null {
  const match = /v?(\d+)\.(\d+)\.(\d+)/.exec(text);

  return match ? match.slice(1, 4).map(Number) : null;
}

function isOlder(version: number[], reference: number[]): boolean {
  for (let i = 0; i < 3; i++) {
    if (version[i] !== reference[i]) return version[i] < reference[i];
  }

  return false;
}

/**
 * Renders happen while the suites are collected, so this runs at import time. An
 * older helm is refused rather than tolerated: helm's own output changes between
 * minor versions (3.18 replaced its JSON Schema validator, rewording every
 * values error), so it would fail here for reasons CI never sees.
 */
export function assertHelmInstalled(): void {
  let installed: string;

  try {
    installed = execFileSync('helm', ['version', '--short'], { encoding: 'utf8' });
  } catch {
    throw new Error('The chart tests need the helm binary on the PATH (brew install helm, or https://helm.sh/docs/intro/install/)');
  }

  const pinned = /HELM_VERSION:\s*(v[\d.]+)/.exec(readFileSync(SETUP_HELM_ACTION, 'utf8'))?.[1];
  const installedVersion = parseVersion(installed);
  const pinnedVersion = pinned ? parseVersion(pinned) : null;

  if (installedVersion && pinnedVersion && isOlder(installedVersion, pinnedVersion)) {
    throw new Error(`The chart tests need helm ${pinned} or newer, the version CI uses (found ${installed.trim()})`);
  }
}

/**
 * A values-schema `pattern` rejection of the value at `path` (dotted, as given to
 * `--set`). Matches the path, never helm's sentence around it: the validator
 * writes `users.0.password: Does not match pattern` in one version and
 * `at '/users/0/password': ... does not match pattern` in the next.
 */
export function schemaPatternRejection(path: string): RegExp {
  const segments = path.split(/[.[\]]+/).filter(Boolean);

  return new RegExp(`${segments.join('[./]')}\\b.*does not match pattern`, 'i');
}
