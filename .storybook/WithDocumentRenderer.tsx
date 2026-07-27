import { type DocumentProps, usePDF } from '@react-pdf/renderer';
import type { Decorator } from '@storybook/react';
import React, { type ReactElement } from 'react';

/**
 * Renders a story that IS a `@react-pdf/renderer` <Document> into a real PDF and
 * shows it in the browser's native PDF reader (an <iframe> on the blob URL), so a
 * story previews the actual paginated output, page framing and per-page footer,
 * exactly as it prints, rather than an HTML approximation of it.
 */
function PdfReader({ document }: { document: ReactElement<DocumentProps> }) {
  const [instance] = usePDF({ document });

  if (instance.loading) {
    return <div>Rendering the PDF...</div>;
  }

  if (instance.error) {
    return <div>Something went wrong: {instance.error}</div>;
  }

  if (!instance.url) {
    return <div>Initializing the renderer</div>;
  }

  return <iframe title="PDF preview" src={instance.url} style={{ display: 'block', width: '100%', height: '100vh', border: 'none' }} />;
}

export const WithDocumentRenderer: Decorator = (Story, context) => {
  // usePDF does NOT re-render when its document prop changes, only on mount, so a
  // locale switch would keep the old PDF. Keying the reader on the locale remounts
  // it, re-rendering the document in the newly selected language.
  return <PdfReader key={String(context.globals.locale)} document={(<Story />) as ReactElement<DocumentProps>} />;
};
