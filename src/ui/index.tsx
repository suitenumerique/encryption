import '@gouvfr-lasuite/cunningham-react/icons';
import '@gouvfr-lasuite/cunningham-react/style';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import '@encryption/src/i18n';
import { MSG_INTERFACE_RESIZE } from '@encryption/src/shared/constants';
import { App } from '@encryption/src/ui/App';

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
      const observer = new ResizeObserver(() => {
        const height = document.body.scrollHeight;
        window.parent.postMessage({ type: MSG_INTERFACE_RESIZE, height }, '*');
      });

      observer.observe(document.body);
    }
  }
}
