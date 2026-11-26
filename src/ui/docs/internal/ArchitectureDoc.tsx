import Markdown, { type Components } from 'react-markdown';
import remarkGfm from 'remark-gfm';

import architectureSource from '@encryption/architecture.md?raw';
import { DocsLayout } from '@encryption/src/ui/docs/DocsLayout';
import { Mermaid } from '@encryption/src/ui/docs/components/Mermaid';
import { createMdxComponentsWithMermaid } from '@encryption/src/ui/docs/mdx-components';

/**
 * The repository's architecture document, rendered with the same components as
 * the shipped documentation.
 *
 * Imported as a RAW STRING and rendered at runtime rather than compiled as MDX:
 * a second MDX plugin for `.md` conflicts with the one addon-docs installs for
 * `.mdx` (it worked in a production build but broke the dev server). This keeps
 * ONE copy of the file at the repo root, still plain GitHub-flavoured markdown
 * that renders for auditors, with its ```mermaid fences turned into diagrams by
 * the shared `code` override.
 *
 * English only on purpose: it is an audit artefact, not a user-facing page.
 */
// The document gives each section a stable anchor with an `<a id="…"></a>` line
// right before its heading, so links survive a heading's rewording on GitHub.
// react-markdown escapes raw HTML (no HTML plugin is wanted here), so those lines
// are removed and their id is moved onto the heading that follows instead.
const ANCHOR_LINE = /^<a id="([^"]+)"><\/a>\n+(#{2,3} .*)$/gm;

const headingIds = new Map<string, string>();
const renderedSource = architectureSource.replace(ANCHOR_LINE, (_line, id: string, heading: string) => {
  headingIds.set(heading.replace(/^#+ /, '').trim(), id);

  return heading;
});

function textOf(node: unknown): string {
  if (!node || typeof node !== 'object') return '';
  const n = node as { type?: string; value?: string; children?: unknown[] };
  if (n.type === 'text') return n.value ?? '';

  return (n.children ?? []).map(textOf).join('');
}

// Built here, not imported from the shared map: this is the ONLY consumer of
// mermaid, and it is never part of the shipped interface.
const components: Components = {
  ...createMdxComponentsWithMermaid((chart) => <Mermaid chart={chart} />),
  h2: ({ node, children }) => <h2 id={headingIds.get(textOf(node))}>{children}</h2>,
  h3: ({ node, children }) => <h3 id={headingIds.get(textOf(node))}>{children}</h3>,
};

export function ArchitectureDoc() {
  return (
    <DocsLayout>
      <Markdown remarkPlugins={[remarkGfm]} components={components}>
        {renderedSource}
      </Markdown>
    </DocsLayout>
  );
}
