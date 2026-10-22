import { renderToMjml } from '@faire/mjml-react/utils/renderToMjml';
import mjml2html from 'mjml-browser';
import { PropsWithChildren, ReactElement, useEffect, useState } from 'react';

/**
 * Transform an MJML React tree into the final email HTML, the same output the
 * server mailer produces (mjml v5 is async). Shared by the plain HTML preview
 * and the client-overview (which also derives the plaintext from this HTML, so
 * both sides show what a real mail client would receive). Throws render errors
 * so a story fails loudly rather than showing a blank frame.
 */
export function useEmailHtml(content: ReactElement): string | null {
  const [html, setHtml] = useState<string | null>(null);
  const [error, setError] = useState<Error | null>(null);

  const mjmlContent = renderToMjml(content);

  useEffect(() => {
    let cancelled = false;

    mjml2html(mjmlContent)
      .then((transformResult) => {
        if (cancelled) return;

        if (transformResult.errors.length > 0) {
          setError(new Error(transformResult.errors.map((err) => err.formattedMessage).join('\n')));
        } else {
          setHtml(transformResult.html);
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err : new Error(String(err)));
      });

    return () => {
      cancelled = true;
    };
  }, [mjmlContent]);

  if (error) throw error;

  return html;
}

export function StorybookRendererLayout(props: PropsWithChildren) {
  const html = useEmailHtml(props.children as ReactElement);

  if (html === null) return null;

  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
