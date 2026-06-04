import '@gouvfr-lasuite/cunningham-react/icons';
import '@gouvfr-lasuite/cunningham-react/style';
import '@gouvfr-lasuite/ui-kit/style';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { DemoApp } from '@encryption/src/demo/DemoApp';

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Root element not found');
}

createRoot(rootElement).render(
  <StrictMode>
    <DemoApp />
  </StrictMode>
);
