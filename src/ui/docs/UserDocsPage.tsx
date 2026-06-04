import { MDXProvider } from '@mdx-js/react';

import { DocsLayout } from '@encryption/src/ui/docs/DocsLayout';
import { Alert, CodeBlock } from '@encryption/src/ui/docs/components';
import FaqContent from '@encryption/src/ui/docs/user/faq.mdx';

const mdxComponents = {
  Alert,
  CodeBlock,
};

export function UserDocsPage() {
  return (
    <DocsLayout>
      <MDXProvider components={mdxComponents}>
        <FaqContent />
      </MDXProvider>
    </DocsLayout>
  );
}
