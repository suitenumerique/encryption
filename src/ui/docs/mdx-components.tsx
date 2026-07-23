import hljs from 'highlight.js/lib/common';
import type { ReactNode } from 'react';

import { Alert, CodeBlock } from '@encryption/src/ui/docs/components';

function textOf(node: ReactNode): string {
  if (typeof node === 'string') return node;
  if (Array.isArray(node)) return node.map(textOf).join('');
  if (node && typeof node === 'object' && 'props' in node) {
    return textOf((node as { props: { children?: ReactNode } }).props.children);
  }

  return '';
}

/**
 * The renderer markdown fences resolve to: syntax highlighting for every
 * language, driven by the fence's `language-*` class. The source files stay
 * plain GitHub-flavoured markdown, so GitHub renders them natively too.
 *
 * `renderMermaid` is INJECTED rather than imported. Only the architecture
 * document (Storybook-only) contains mermaid fences, and importing the renderer
 * here would pull ~1 MB of mermaid diagram chunks into the shipped interface,
 * which serves no purpose in production.
 */
function makeCode(renderMermaid?: (chart: string) => ReactNode) {
  return function Code({ className, children }: { className?: string; children?: ReactNode }) {
    const language = /language-(\w+)/.exec(className ?? '')?.[1];
    const source = textOf(children);

    // Inline `code` has no language class and must stay inline.
    if (!language) {
      return <code className={className}>{children}</code>;
    }

    if (language === 'mermaid') {
      // Without a renderer the diagram source is shown as-is rather than lost.
      return renderMermaid ? renderMermaid(source) : <code className={className}>{source}</code>;
    }

    const highlighted = hljs.getLanguage(language) ? hljs.highlight(source, { language }).value : hljs.highlightAuto(source).value;

    return <code className={`hljs language-${language}`} dangerouslySetInnerHTML={{ __html: highlighted }} />;
  };
}

/** Map for the SHIPPED documentation pages. Deliberately mermaid-free. */
export const mdxComponents = {
  Alert,
  CodeBlock,
  code: makeCode(),
};

/**
 * Map for documents that contain mermaid, i.e. architecture.md, which is only
 * rendered in Storybook. Keeping it in a separate export is what keeps mermaid
 * out of the production bundle.
 */
export function createMdxComponentsWithMermaid(renderMermaid: (chart: string) => ReactNode) {
  return {
    Alert,
    CodeBlock,
    code: makeCode(renderMermaid),
  };
}
