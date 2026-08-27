import type { Lockfile } from '@encryption/src/security/lockfile-policy';
import { checkLockfile } from '@encryption/src/security/lockfile-policy';

const registryEntry = {
  version: '1.0.0',
  resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz',
  integrity: 'sha512-deadbeef',
};

function lockfileWith(packages: Lockfile['packages']): Lockfile {
  return { lockfileVersion: 3, packages: { '': { version: '0.0.0' }, ...packages } };
}

describe('checkLockfile', () => {
  it('accepts a tree fully resolved from the public registry with integrity hashes', () => {
    expect(checkLockfile(lockfileWith({ 'node_modules/left-pad': registryEntry }))).toEqual([]);
  });

  it('rejects a dependency pulled from another registry', () => {
    const violations = checkLockfile(
      lockfileWith({
        'node_modules/left-pad': { ...registryEntry, resolved: 'https://evil.example.com/left-pad-1.0.0.tgz' },
      })
    );

    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ kind: 'foreign-registry', path: 'node_modules/left-pad' });
  });

  it('rejects a dependency with no integrity hash, which npm ci cannot verify', () => {
    const { integrity: _integrity, ...withoutIntegrity } = registryEntry;
    const violations = checkLockfile(lockfileWith({ 'node_modules/left-pad': withoutIntegrity }));

    expect(violations).toHaveLength(1);
    expect(violations[0].kind).toBe('missing-integrity');
  });

  it('rejects a git dependency, which has no verifiable tarball', () => {
    const violations = checkLockfile(
      lockfileWith({ 'node_modules/left-pad': { version: '1.0.0', resolved: 'git+ssh://git@github.com/x/left-pad.git#abc' } })
    );

    expect(violations).toHaveLength(1);
    expect(violations[0].kind).toBe('non-registry-source');
  });

  it('rejects a dependency with no resolved URL at all', () => {
    expect(checkLockfile(lockfileWith({ 'node_modules/left-pad': { version: '1.0.0' } }))[0].kind).toBe('non-registry-source');
  });

  it('ignores the root project and workspace links, which have no tarball', () => {
    expect(checkLockfile(lockfileWith({ 'node_modules/local': { link: true, resolved: undefined } }))).toEqual([]);
  });

  it('rejects an old lockfile format that does not carry integrity for every entry', () => {
    const violations = checkLockfile({ lockfileVersion: 1, packages: {} });

    expect(violations).toHaveLength(1);
    expect(violations[0].kind).toBe('lockfile-version');
  });
});
