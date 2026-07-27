import type { ReactNode } from 'react';

interface DocsLayoutProps {
  children: ReactNode;
}

export function DocsLayout({ children }: DocsLayoutProps) {
  return (
    <div
      style={{
        maxWidth: 800,
        margin: '0 auto',
        padding: 'var(--c--globals--spacings--lg) var(--c--globals--spacings--md)',
        color: 'var(--c--contextuals--content--semantic--neutral--primary)',
        lineHeight: 1.7,
        fontFamily: 'var(--c--globals--font--families--base)',
      }}
    >
      <style>{`
        .docs-content h1 {
          color: var(--c--globals--colors--brand-500);
          font-size: var(--c--globals--font--sizes--h2);
          font-weight: var(--c--globals--font--weights--bold);
          margin: 0 0 var(--c--globals--spacings--md);
          padding-bottom: var(--c--globals--spacings--base);
          border-bottom: 2px solid var(--c--globals--colors--brand-500);
        }
        .docs-content h2 {
          color: var(--c--contextuals--content--semantic--neutral--primary);
          font-size: var(--c--globals--font--sizes--h3);
          font-weight: var(--c--globals--font--weights--bold);
          margin: var(--c--globals--spacings--lg) 0 var(--c--globals--spacings--sm);
        }
        .docs-content h3 {
          color: var(--c--contextuals--content--semantic--neutral--secondary);
          font-size: var(--c--globals--font--sizes--h4);
          margin: var(--c--globals--spacings--md) 0 var(--c--globals--spacings--t);
        }
        .docs-content p {
          margin: var(--c--globals--spacings--t) 0;
          font-size: var(--c--globals--font--sizes--ml);
        }
        .docs-content a {
          color: var(--c--globals--colors--brand-500);
          text-decoration: underline;
        }
        .docs-content code {
          background: var(--c--contextuals--background--surface--tertiary);
          padding: 2px 6px;
          border-radius: 3px;
          font-size: var(--c--globals--font--sizes--s);
          color: var(--c--globals--colors--brand-500);
        }
        .docs-content pre code { background: none; padding: 0; color: inherit; }
        .docs-content blockquote {
          border-left: 4px solid var(--c--globals--colors--brand-500);
          margin: var(--c--globals--spacings--base) 0;
          padding: var(--c--globals--spacings--t) var(--c--globals--spacings--base);
          background: var(--c--contextuals--background--surface--tertiary);
        }
        .docs-content table { width: 100%; border-collapse: collapse; margin: var(--c--globals--spacings--base) 0; font-size: var(--c--globals--font--sizes--s); }
        .docs-content th {
          text-align: left;
          padding: var(--c--globals--spacings--t) var(--c--globals--spacings--sm);
          background: var(--c--contextuals--background--surface--tertiary);
          border-bottom: 2px solid var(--c--globals--colors--brand-500);
          font-weight: var(--c--globals--font--weights--bold);
        }
        .docs-content td {
          padding: var(--c--globals--spacings--t) var(--c--globals--spacings--sm);
          border-bottom: 1px solid var(--c--contextuals--border--surface--primary);
        }
        /* Syntax highlighting driven by the Cunningham palette rather than a
           packaged highlight.js theme, so code follows the light/dark theme
           instead of pinning one set of token colours onto whichever background
           the theme resolved to. */
        /* Uses the tertiary surface, not the secondary one: secondary resolves to
           the SAME grey as the page surface in the light theme (both gray-000),
           so table headers and inline code had no visible tint there while
           standing out in dark. Tertiary differs from the page in both themes. */
        .docs-content .hljs { color: var(--c--contextuals--content--semantic--neutral--primary); background: none; }
        .docs-content .hljs-comment, .docs-content .hljs-quote { color: var(--c--contextuals--content--semantic--neutral--secondary); font-style: italic; }
        .docs-content .hljs-keyword, .docs-content .hljs-selector-tag, .docs-content .hljs-literal, .docs-content .hljs-built_in { color: var(--c--globals--colors--brand-500); }
        .docs-content .hljs-string, .docs-content .hljs-attr, .docs-content .hljs-symbol { color: var(--c--globals--colors--success-600); }
        .docs-content .hljs-number, .docs-content .hljs-regexp { color: var(--c--globals--colors--warning-600); }
        .docs-content .hljs-title, .docs-content .hljs-name, .docs-content .hljs-section { color: var(--c--globals--colors--info-600); font-weight: 600; }
        .docs-content .hljs-tag { color: var(--c--contextuals--content--semantic--neutral--secondary); }
        .docs-content .hljs-meta, .docs-content .hljs-doctag { color: var(--c--globals--colors--error-600); }
        .docs-content hr { border: none; border-top: 1px solid var(--c--contextuals--border--surface--primary); margin: var(--c--globals--spacings--lg) 0; }
        .docs-content ol, .docs-content ul { padding-left: var(--c--globals--spacings--md); margin: var(--c--globals--spacings--t) 0; }
        .docs-content li { margin: var(--c--globals--spacings--3xs) 0; font-size: var(--c--globals--font--sizes--ml); }
      `}</style>
      <div className="docs-content">{children}</div>
    </div>
  );
}
