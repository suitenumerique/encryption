import { checkActionReference, checkWorkflow, checkWorkflowPermissions, extractUses } from '@encryption/src/security/actions-pinning';

const SHA = '08c6903cd8c0fde910a37f88322edcfb5dd907a8';

function reference(uses: string) {
  return { file: 'ci.yml', line: 1, uses };
}

describe('extractUses', () => {
  it('finds every action reference with its line number', () => {
    const content = ['jobs:', '  build:', '    steps:', `      - uses: actions/checkout@${SHA} # v5`, '      - run: npm ci'].join('\n');

    expect(extractUses('ci.yml', content)).toEqual([{ file: 'ci.yml', line: 4, uses: `actions/checkout@${SHA}` }]);
  });

  it('ignores a commented-out reference', () => {
    expect(extractUses('ci.yml', '      # - uses: actions/checkout@v5')).toEqual([]);
  });

  it('handles a quoted reference', () => {
    expect(extractUses('ci.yml', `      - uses: "actions/checkout@${SHA}"`)[0].uses).toBe(`actions/checkout@${SHA}`);
  });
});

describe('checkActionReference', () => {
  it('accepts a full commit SHA', () => {
    expect(checkActionReference(reference(`actions/checkout@${SHA}`))).toBeNull();
  });

  it('rejects a version tag, which the maintainer can repoint', () => {
    expect(checkActionReference(reference('actions/checkout@v5'))?.detail).toContain('mutable ref "v5"');
  });

  it('rejects a branch, which changes on every push with no release step', () => {
    expect(checkActionReference(reference('numerique-gouv/action-trivy-cache@main'))?.detail).toContain('mutable ref "main"');
  });

  it('rejects a reference with no ref at all', () => {
    expect(checkActionReference(reference('actions/checkout'))?.detail).toContain('no ref at all');
  });

  it('accepts a local action, which is reviewed with the rest of the repository', () => {
    expect(checkActionReference(reference('./.github/actions/setup'))).toBeNull();
  });

  it('accepts a container action pinned to an image digest', () => {
    expect(checkActionReference(reference('docker://ghcr.io/org/tool@sha256:abc'))).toBeNull();
  });

  it('rejects a container action pinned to an image tag', () => {
    expect(checkActionReference(reference('docker://ghcr.io/org/tool:v1'))?.kind).toBe('unpinned-action');
  });

  it('rejects a short SHA, which is not collision-bound the way a full one is', () => {
    expect(checkActionReference(reference('actions/checkout@08c6903'))?.kind).toBe('unpinned-action');
  });
});

describe('checkWorkflowPermissions', () => {
  it('accepts a workflow that states its permissions', () => {
    expect(checkWorkflowPermissions('ci.yml', 'permissions:\n  contents: read\n')).toBeNull();
  });

  it('rejects a workflow that inherits the repository default', () => {
    expect(checkWorkflowPermissions('ci.yml', 'jobs:\n  build:\n    runs-on: ubuntu-latest\n')?.kind).toBe('missing-permissions');
  });
});

describe('checkWorkflow', () => {
  it('reports both an unpinned action and a missing permissions block', () => {
    expect(checkWorkflow('ci.yml', '      - uses: actions/checkout@v5\n').map((violation) => violation.kind)).toEqual([
      'unpinned-action',
      'missing-permissions',
    ]);
  });

  it('passes a workflow that is pinned and scoped', () => {
    expect(checkWorkflow('ci.yml', `permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@${SHA}\n`)).toEqual([]);
  });
});
