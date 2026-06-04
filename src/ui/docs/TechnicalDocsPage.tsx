import { MDXProvider } from '@mdx-js/react';

import { DocsLayout } from '@encryption/src/ui/docs/DocsLayout';
import { Alert, CodeBlock } from '@encryption/src/ui/docs/components';
import IntegrationContent from '@encryption/src/ui/docs/technical/integration.mdx';

const mdxComponents = {
  Alert,
  CodeBlock,
};

export function TechnicalDocsPage() {
  return (
    <DocsLayout>
      <MDXProvider components={mdxComponents}>
        <IntegrationContent />
      </MDXProvider>
    </DocsLayout>
  );
}
