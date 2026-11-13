import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import '@encryption/src/i18n';
import { MaintenanceTool } from '@encryption/src/maintenance/tool/MaintenanceTool';

createRoot(document.getElementById('root') as HTMLElement).render(
  <StrictMode>
    <MaintenanceTool />
  </StrictMode>
);
