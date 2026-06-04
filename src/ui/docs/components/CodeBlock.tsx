import type { ReactNode } from 'react';

interface CodeBlockProps {
  children: ReactNode;
  language?: string;
}

export function CodeBlock({ children, language }: CodeBlockProps) {
  return (
    <pre
      style={{
        background: 'var(--c--contextuals--background--surface--tertiary, #1e1e1e)',
        color: 'var(--c--contextuals--content--surface--tertiary, #d4d4d4)',
        padding: 'var(--c--globals--spacings--4, 16px)',
        borderRadius: 4,
        overflow: 'auto',
        fontSize: 'var(--c--globals--font--sizes--s, 13px)',
        lineHeight: 1.5,
        margin: 'var(--c--globals--spacings--4, 16px) 0',
      }}
    >
      {language && (
        <div
          style={{
            color: 'var(--c--contextuals--content--surface--secondary, #888)',
            fontSize: 11,
            marginBottom: 'var(--c--globals--spacings--2, 8px)',
          }}
        >
          {language}
        </div>
      )}
      <code>{children}</code>
    </pre>
  );
}
