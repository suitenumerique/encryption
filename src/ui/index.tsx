import '@fontsource-variable/inter';
import '@gouvfr-lasuite/cunningham-react/icons';
import '@gouvfr-lasuite/cunningham-react/style';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import '@encryption/src/i18n';
import { App } from '@encryption/src/ui/App';
import { applyBrandFont } from '@encryption/src/ui/brand-font';
import { installErrorReporting } from '@encryption/src/ui/monitoring';

// Point Cunningham at the deployment's brand font (if any) before the first paint.
applyBrandFont();

// Before anything else can throw. Posts to our own backend only; see the module.
installErrorReporting();

// Auth routes (/login, /auth/callback) are opened in a new tab, not in an iframe.
// All other routes must be inside an iframe.
const isAuthRoute = window.location.pathname === '/login' || window.location.pathname === '/auth/callback';
const isIframe = window.self !== window.top;

// Revealing the direct-access warning.
if (!isIframe && !isAuthRoute) {
  const accessError = document.getElementById('access-error');
  const root = document.getElementById('root');

  if (accessError) accessError.style.display = 'block';
  if (root) root.style.display = 'none';
}

if (isIframe || isAuthRoute) {
  const rootElement = document.getElementById('root');

  if (rootElement) {
    createRoot(rootElement).render(
      <StrictMode>
        <App />
      </StrictMode>
    );
  }
}
