/**
 * Invariants the lockfile must hold for `npm ci` to be a trustworthy install.
 *
 * The lockfile is what actually pins the ~2200 transitive dependencies that
 * `package.json` says nothing about. These checks assert that every one of them is
 * fetched from the public registry and verified against a hash, so that a
 * registry substitution, a dependency-confusion entry, a git dependency or an
 * arbitrary tarball URL cannot slip in through a rebase or a careless `npm install`.
 */
export interface LockfileEntry {
  version?: string;
  dev?: boolean;
  optional?: boolean;
  resolved?: string;
  integrity?: string;
  link?: boolean;
}

export interface Lockfile {
  lockfileVersion?: number;
  packages: Record<string, LockfileEntry>;
}

export const ALLOWED_REGISTRY_HOSTS = ['registry.npmjs.org'] as const;

export const MINIMUM_LOCKFILE_VERSION = 3;

export interface LockfileViolation {
  kind: 'missing-integrity' | 'foreign-registry' | 'non-registry-source' | 'lockfile-version';
  path: string;
  detail: string;
}

function isLocalWorkspaceEntry(path: string, entry: LockfileEntry): boolean {
  // The root project (`""`) and workspace links have no tarball to verify.
  return path === '' || entry.link === true;
}

export function checkLockfile(lock: Lockfile): LockfileViolation[] {
  const violations: LockfileViolation[] = [];
  const allowedHosts = new Set<string>(ALLOWED_REGISTRY_HOSTS);

  if ((lock.lockfileVersion ?? 0) < MINIMUM_LOCKFILE_VERSION) {
    violations.push({
      kind: 'lockfile-version',
      path: '(lockfile)',
      detail: `lockfileVersion ${lock.lockfileVersion} is below the required ${MINIMUM_LOCKFILE_VERSION}`,
    });
  }

  for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    if (isLocalWorkspaceEntry(path, entry)) continue;

    const { resolved } = entry;

    if (!resolved) {
      violations.push({ kind: 'non-registry-source', path, detail: 'no `resolved` URL' });
      continue;
    }

    if (!resolved.startsWith('https://')) {
      violations.push({ kind: 'non-registry-source', path, detail: `resolved from a non-https source: ${resolved}` });
      continue;
    }

    let host: string;

    try {
      host = new URL(resolved).host;
    } catch {
      violations.push({ kind: 'non-registry-source', path, detail: `unparseable resolved URL: ${resolved}` });
      continue;
    }

    if (!allowedHosts.has(host)) {
      violations.push({ kind: 'foreign-registry', path, detail: `resolved from ${host}` });
    }

    if (!entry.integrity) {
      violations.push({ kind: 'missing-integrity', path, detail: 'no `integrity` hash, so `npm ci` cannot verify the tarball' });
    }
  }

  return violations;
}
