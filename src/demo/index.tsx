import '@gouvfr-lasuite/ui-components/style';
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
