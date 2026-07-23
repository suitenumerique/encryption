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
        padding: 'var(--c--globals--spacings--8, 32px) var(--c--globals--spacings--6, 24px)',
        color: 'var(--c--contextuals--content--semantic--neutral--primary, #161616)',
        lineHeight: 1.7,
        fontFamily: 'var(--c--globals--font--families--base, system-ui, sans-serif)',
      }}
    >
      <style>{`
        .docs-content h1 {
          color: var(--c--globals--colors--brand-500, #000091);
          font-size: var(--c--globals--font--sizes--h2, 28px);
          font-weight: var(--c--globals--font--weights--bold, 700);
          margin: 0 0 var(--c--globals--spacings--6, 24px);
          padding-bottom: var(--c--globals--spacings--4, 16px);
          border-bottom: 2px solid var(--c--globals--colors--brand-500, #000091);
        }
        .docs-content h2 {
          color: var(--c--contextuals--content--semantic--neutral--primary, #161616);
          font-size: var(--c--globals--font--sizes--h3, 21px);
          font-weight: var(--c--globals--font--weights--bold, 700);
          margin: var(--c--globals--spacings--8, 32px) 0 var(--c--globals--spacings--3, 12px);
        }
        .docs-content h3 {
          color: var(--c--contextuals--content--semantic--neutral--secondary, #3a3a3a);
          font-size: var(--c--globals--font--sizes--h4, 17px);
          margin: var(--c--globals--spacings--6, 24px) 0 var(--c--globals--spacings--2, 8px);
        }
        .docs-content p {
          margin: var(--c--globals--spacings--2, 8px) 0;
          font-size: var(--c--globals--font--sizes--m, 15px);
        }
        .docs-content a {
          color: var(--c--globals--colors--brand-500, #000091);
          text-decoration: underline;
        }
        .docs-content code {
          background: var(--c--contextuals--background--surface--tertiary, #f5f5fe);
          padding: 2px 6px;
          border-radius: 3px;
          font-size: var(--c--globals--font--sizes--s, 13px);
          color: var(--c--globals--colors--brand-500, #000091);
        }
        .docs-content pre code { background: none; padding: 0; color: inherit; }
        .docs-content blockquote {
          border-left: 4px solid var(--c--globals--colors--brand-500, #000091);
          margin: var(--c--globals--spacings--4, 16px) 0;
          padding: var(--c--globals--spacings--2, 8px) var(--c--globals--spacings--4, 16px);
          background: var(--c--contextuals--background--surface--tertiary, #f5f5fe);
        }
        .docs-content table { width: 100%; border-collapse: collapse; margin: var(--c--globals--spacings--4, 16px) 0; font-size: var(--c--globals--font--sizes--s, 14px); }
        .docs-content th {
          text-align: left;
          padding: var(--c--globals--spacings--2, 8px) var(--c--globals--spacings--3, 12px);
          background: var(--c--contextuals--background--surface--tertiary, #f5f5fe);
          border-bottom: 2px solid var(--c--globals--colors--brand-500, #000091);
          font-weight: var(--c--globals--font--weights--bold, 700);
        }
        .docs-content td {
          padding: var(--c--globals--spacings--2, 8px) var(--c--globals--spacings--3, 12px);
          border-bottom: 1px solid var(--c--contextuals--border--surface--primary, #e5e5e5);
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
        .docs-content .hljs-string, .docs-content .hljs-attr, .docs-content .hljs-symbol { color: var(--c--globals--colors--success-600, #18753c); }
        .docs-content .hljs-number, .docs-content .hljs-regexp { color: var(--c--globals--colors--warning-600, #b34000); }
        .docs-content .hljs-title, .docs-content .hljs-name, .docs-content .hljs-section { color: var(--c--globals--colors--info-600, #0063cb); font-weight: 600; }
        .docs-content .hljs-tag { color: var(--c--contextuals--content--semantic--neutral--secondary); }
        .docs-content .hljs-meta, .docs-content .hljs-doctag { color: var(--c--globals--colors--error-600, #ce0500); }
        .docs-content hr { border: none; border-top: 1px solid var(--c--contextuals--border--surface--primary, #e5e5e5); margin: var(--c--globals--spacings--8, 32px) 0; }
        .docs-content ol, .docs-content ul { padding-left: var(--c--globals--spacings--6, 24px); margin: var(--c--globals--spacings--2, 8px) 0; }
        .docs-content li { margin: var(--c--globals--spacings--1, 4px) 0; font-size: var(--c--globals--font--sizes--m, 15px); }
      `}</style>
      <div className="docs-content">{children}</div>
    </div>
  );
}
