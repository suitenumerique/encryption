import Markdown from 'react-markdown';
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
// Built here, not imported from the shared map: this is the ONLY consumer of
// mermaid, and it is never part of the shipped interface.
const components = createMdxComponentsWithMermaid((chart) => <Mermaid chart={chart} />);

export function ArchitectureDoc() {
  return (
    <DocsLayout>
      <Markdown remarkPlugins={[remarkGfm]} components={components}>
        {architectureSource}
      </Markdown>
    </DocsLayout>
  );
}
