import { MDXProvider } from '@mdx-js/react';
import { Suspense, lazy } from 'react';
import { useTranslation } from 'react-i18next';

import { DocsLayout } from '@encryption/src/ui/docs/DocsLayout';
import { mdxComponents } from '@encryption/src/ui/docs/mdx-components';

// One chunk per locale, so only the language being read is fetched. English is
// the base file and translations carry a `_<locale>` suffix; both are plain
// markdown that GitHub renders, which is the point of translating by file
// rather than by i18n key. This is the ONLY translated document.
const CONTENT = {
  en: lazy(() => import('@encryption/src/ui/docs/user/faq.mdx')),
  fr: lazy(() => import('@encryption/src/ui/docs/user/faq_fr.mdx')),
};

export function UserDocsPage() {
  const { i18n } = useTranslation('common');
  const locale = i18n.language.startsWith('en') ? 'en' : 'fr';
  const FaqContent = CONTENT[locale];

  return (
    <DocsLayout>
      <MDXProvider components={mdxComponents}>
        <Suspense fallback={null}>
          <FaqContent />
        </Suspense>
      </MDXProvider>
    </DocsLayout>
  );
}
