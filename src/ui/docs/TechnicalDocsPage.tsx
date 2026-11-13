import { MDXProvider } from '@mdx-js/react';

import { DocsLayout } from '@encryption/src/ui/docs/DocsLayout';
import { mdxComponents } from '@encryption/src/ui/docs/mdx-components';
import IntegrationContent from '@encryption/src/ui/docs/technical/integration.mdx';

export function TechnicalDocsPage() {
  return (
    <DocsLayout>
      <MDXProvider components={mdxComponents}>
        <IntegrationContent />
      </MDXProvider>
    </DocsLayout>
  );
}
