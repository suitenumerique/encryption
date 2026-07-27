import '@fontsource-variable/inter';
import '@gouvfr-lasuite/cunningham-react/icons';
import '@gouvfr-lasuite/cunningham-react/style';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import '@encryption/src/i18n';
import { MSG_INTERFACE_RESIZE } from '@encryption/src/shared/constants';
import { App } from '@encryption/src/ui/App';
import { applyBrandFont } from '@encryption/src/ui/brand-font';

// Point Cunningham at the deployment's brand font (if any) before the first paint.
applyBrandFont();

// Auth routes (/login, /auth/callback) are opened in a new tab, not in an iframe.
// All other routes must be inside an iframe.
const isAuthRoute = window.location.pathname === '/login' || window.location.pathname === '/auth/callback';
const isIframe = window.self !== window.top;

if (isIframe || isAuthRoute) {
  const rootElement = document.getElementById('root');

  if (rootElement) {
    createRoot(rootElement).render(
      <StrictMode>
        <App />
      </StrictMode>
    );

    // Auto-resize: communicate content height to the parent frame (only in iframe mode).
    // We measure `document.body`, NOT `document.documentElement`:
    // `<html>` can pick up the iframe's own set height via `height: 100%` /
    // normalize styles, which creates a feedback loop with the parent's
    // resize handler — every interaction ratchets the iframe ~2px taller
    // each time. `<body>` only reflects actual content and is stable.
    if (isIframe) {
      let lastPosted = -1;
      let timer: ReturnType<typeof setTimeout> | undefined;

      const post = () => {
        const height = document.body.scrollHeight;
        if (height === lastPosted) return;
        lastPosted = height;
        window.parent.postMessage({ type: MSG_INTERFACE_RESIZE, height }, '*');
      };

      // A single interaction triggers a burst of reflows (a loading state, a step
      // change, and — when the new height crosses the parent viewport — a parent
      // scrollbar toggling our width, which rewraps text and changes our height
      // again). Posting each one resizes the iframe repeatedly and flickers that
      // scrollbar. Debounce so the burst settles into a single post.
      const observer = new ResizeObserver(() => {
        clearTimeout(timer);
        timer = setTimeout(post, 50);
      });

      observer.observe(document.body);
    }
  }
}
