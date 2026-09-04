import mermaid from 'mermaid';
import { useEffect, useRef, useState } from 'react';

import { toTrustedMarkup } from '@encryption/src/ui/trusted-markup';

interface MermaidProps {
  chart: string;
}

let initialized = false;

/**
 * Renders one mermaid diagram.
 *
 * Deliberately driven by a ```mermaid CODE FENCE rather than a JSX component in
 * the markdown: the architecture document has to stay readable on GitHub, which
 * renders mermaid fences natively but would show raw JSX. See the `code`
 * override in `mdxComponents` for how a fence reaches this component.
 */
export function Mermaid({ chart }: MermaidProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!initialized) {
      mermaid.initialize({ startOnLoad: false, theme: 'neutral', securityLevel: 'strict' });
      initialized = true;
    }

    let cancelled = false;
    // The id must be unique per render: mermaid caches by it.
    const id = `mermaid-${Math.random().toString(36).slice(2)}`;

    mermaid
      .render(id, chart)
      .then(({ svg }) => {
        if (cancelled || !containerRef.current) return;

        containerRef.current.innerHTML = toTrustedMarkup(svg);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError((err as Error).message);
      });

    return () => {
      cancelled = true;
    };
  }, [chart]);

  if (error) {
    // Fall back to the source rather than an empty box: a diagram that fails to
    // parse is still information, and silently rendering nothing hides the typo.
    return (
      <pre style={{ background: '#fff4f4', border: '1px solid #e5c2c2', borderRadius: 4, padding: 16, overflow: 'auto', fontSize: 13 }}>{chart}</pre>
    );
  }

  return <div ref={containerRef} style={{ margin: '16px 0', overflow: 'auto' }} />;
}
