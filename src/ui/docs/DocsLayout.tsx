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
        color: 'var(--c--contextuals--content--surface--primary, #161616)',
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
          color: var(--c--contextuals--content--surface--primary, #161616);
          font-size: var(--c--globals--font--sizes--h3, 21px);
          font-weight: var(--c--globals--font--weights--bold, 700);
          margin: var(--c--globals--spacings--8, 32px) 0 var(--c--globals--spacings--3, 12px);
        }
        .docs-content h3 {
          color: var(--c--contextuals--content--surface--secondary, #3a3a3a);
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
          background: var(--c--contextuals--background--surface--secondary, #f5f5fe);
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
          background: var(--c--contextuals--background--surface--secondary, #f5f5fe);
        }
        .docs-content table { width: 100%; border-collapse: collapse; margin: var(--c--globals--spacings--4, 16px) 0; font-size: var(--c--globals--font--sizes--s, 14px); }
        .docs-content th {
          text-align: left;
          padding: var(--c--globals--spacings--2, 8px) var(--c--globals--spacings--3, 12px);
          background: var(--c--contextuals--background--surface--secondary, #f5f5fe);
          border-bottom: 2px solid var(--c--globals--colors--brand-500, #000091);
          font-weight: var(--c--globals--font--weights--bold, 700);
        }
        .docs-content td {
          padding: var(--c--globals--spacings--2, 8px) var(--c--globals--spacings--3, 12px);
          border-bottom: 1px solid var(--c--contextuals--border--surface--primary, #e5e5e5);
        }
        .docs-content hr { border: none; border-top: 1px solid var(--c--contextuals--border--surface--primary, #e5e5e5); margin: var(--c--globals--spacings--8, 32px) 0; }
        .docs-content ol, .docs-content ul { padding-left: var(--c--globals--spacings--6, 24px); margin: var(--c--globals--spacings--2, 8px) 0; }
        .docs-content li { margin: var(--c--globals--spacings--1, 4px) 0; font-size: var(--c--globals--font--sizes--m, 15px); }
      `}</style>
      <div className="docs-content">{children}</div>
    </div>
  );
}
