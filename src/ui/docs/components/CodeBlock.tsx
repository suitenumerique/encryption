import hljs from 'highlight.js/lib/common';
import type { ReactNode } from 'react';

import { toTrustedMarkup } from '@encryption/src/ui/trusted-markup';

function textOf(node: ReactNode): string {
  if (typeof node === 'string') return node;
  if (Array.isArray(node)) return node.map(textOf).join('');
  if (node && typeof node === 'object' && 'props' in node) {
    return textOf((node as { props: { children?: ReactNode } }).props.children);
  }

  return '';
}

interface CodeBlockProps {
  children: ReactNode;
  language?: string;
}

/**
 * The documentation calls this component DIRECTLY rather than using markdown
 * fences, so highlighting has to happen here: a `code` renderer wired into the
 * MDX provider only ever sees fenced blocks and would leave every sample in
 * these pages unhighlighted.
 */
export function CodeBlock({ children, language }: CodeBlockProps) {
  const source = textOf(children).replace(/\n$/, '');
  const highlighted = language && hljs.getLanguage(language) ? hljs.highlight(source, { language }).value : hljs.highlightAuto(source).value;

  return (
    <pre
      style={{
        background: 'var(--c--contextuals--background--surface--tertiary)',
        border: '1px solid var(--c--contextuals--border--surface--primary)',
        padding: 'var(--c--globals--spacings--base)',
        borderRadius: 4,
        overflow: 'auto',
        fontSize: 'var(--c--globals--font--sizes--s)',
        lineHeight: 1.5,
        margin: 'var(--c--globals--spacings--base) 0',
      }}
    >
      {language && (
        <div
          style={{
            color: 'var(--c--contextuals--content--semantic--neutral--secondary)',
            fontSize: 11,
            marginBottom: 'var(--c--globals--spacings--t)',
          }}
        >
          {language}
        </div>
      )}
      <code className="hljs" dangerouslySetInnerHTML={{ __html: toTrustedMarkup(highlighted) }} />
    </pre>
  );
}
