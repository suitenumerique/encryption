/**
 * Every third-party GitHub Action must be pinned to a full commit SHA.
 *
 * A tag or a branch is mutable: the maintainer, or anyone holding their
 * credentials, can repoint it and change what runs in this pipeline with no change
 * on our side. That is the tj-actions and trivy-action mechanism. A commit SHA is
 * content-addressed and cannot be repointed.
 *
 * This duplicates one of zizmor's rules on purpose: it runs offline, in a second,
 * with no network and no third-party action of its own, so the rule that protects
 * the workflows is not itself delivered by a workflow dependency.
 */
export const SHA_PATTERN = /^[0-9a-f]{40}$/;

export interface ActionReference {
  file: string;
  line: number;
  uses: string;
}

export interface WorkflowViolation {
  kind: 'unpinned-action' | 'missing-permissions';
  file: string;
  line: number;
  detail: string;
}

export function extractUses(file: string, content: string): ActionReference[] {
  const references: ActionReference[] = [];

  content.split('\n').forEach((rawLine, index) => {
    const line = rawLine.trim();

    if (line.startsWith('#')) return;

    const match = /^-?\s*uses:\s*['"]?([^'"#\s]+)['"]?/.exec(line);

    if (!match) return;

    references.push({ file, line: index + 1, uses: match[1] });
  });

  return references;
}

export function checkActionReference(reference: ActionReference): WorkflowViolation | null {
  const { uses } = reference;

  // A local action or reusable workflow lives in this repository and is reviewed
  // with the rest of the code, so there is nothing external to pin.
  if (uses.startsWith('./')) return null;

  // A container action names an image, which is pinned by digest instead.
  if (uses.startsWith('docker://')) {
    return uses.includes('@sha256:')
      ? null
      : { kind: 'unpinned-action', file: reference.file, line: reference.line, detail: `${uses} is not pinned to an image digest` };
  }

  const at = uses.lastIndexOf('@');

  if (at === -1) {
    return { kind: 'unpinned-action', file: reference.file, line: reference.line, detail: `${uses} has no ref at all` };
  }

  const ref = uses.slice(at + 1);

  if (!SHA_PATTERN.test(ref)) {
    return {
      kind: 'unpinned-action',
      file: reference.file,
      line: reference.line,
      detail: `${uses} is pinned to the mutable ref "${ref}"; use the full commit SHA with the version in a trailing comment`,
    };
  }

  return null;
}

/**
 * A workflow with no `permissions:` block inherits the repository default, which
 * is frequently write. Least privilege has to be stated, not assumed.
 */
export function checkWorkflowPermissions(file: string, content: string): WorkflowViolation | null {
  const hasPermissions = content.split('\n').some((line) => /^\s*permissions:\s*$/.test(line) || /^\s*permissions:\s*\{/.test(line));

  if (hasPermissions) return null;

  return { kind: 'missing-permissions', file, line: 1, detail: 'no `permissions:` block, so the workflow inherits the repository default' };
}

export function checkWorkflow(file: string, content: string): WorkflowViolation[] {
  const violations = extractUses(file, content)
    .map(checkActionReference)
    .filter((violation): violation is WorkflowViolation => violation !== null);

  const permissions = checkWorkflowPermissions(file, content);

  if (permissions) violations.push(permissions);

  return violations;
}
