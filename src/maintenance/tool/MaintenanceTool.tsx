import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { DecryptPanel } from '@encryption/src/maintenance/tool/DecryptPanel';
import { GeneratePanel } from '@encryption/src/maintenance/tool/GeneratePanel';
import { PublicKeyPanel } from '@encryption/src/maintenance/tool/PublicKeyPanel';
import '@encryption/src/maintenance/tool/tool.css';
import { SUPPORTED_LOCALES } from '@encryption/src/shared/locale';

type Tab = 'decrypt' | 'generate' | 'publicKey';

/**
 * The maintenance tool: one page, opened from a file on an isolated computer, that
 * decrypts a product's export with a maintenance phrase, generates that phrase, or
 * gives back the public key of one already held
 * (architecture.md, Appendix E). Plain markup and a small stylesheet rather than the
 * interface's design system, so the single file stays small and readable.
 */
export function MaintenanceTool({ seed }: { seed?: Uint8Array }) {
  const { t, i18n } = useTranslation('common');
  const [tab, setTab] = useState<Tab>('decrypt');

  return (
    <main className="mt-page">
      <header className="mt-header">
        <h1>{t('maintenanceTool.title')}</h1>
        <div className="mt-languages" role="group" aria-label={t('maintenanceTool.language')}>
          {SUPPORTED_LOCALES.map((locale) => (
            <button
              key={locale}
              type="button"
              className="mt-link"
              aria-pressed={i18n.resolvedLanguage === locale}
              onClick={() => void i18n.changeLanguage(locale)}
            >
              {locale.toUpperCase()}
            </button>
          ))}
        </div>
      </header>
      <p className="mt-intro">{t('maintenanceTool.intro')}</p>

      <div className="mt-tabs" role="tablist">
        {(['decrypt', 'generate', 'publicKey'] as const).map((name) => (
          <button
            key={name}
            type="button"
            role="tab"
            id={`mt-tab-${name}`}
            aria-selected={tab === name}
            aria-controls={`mt-tabpanel-${name}`}
            onClick={() => setTab(name)}
          >
            {t(`maintenanceTool.tabs.${name}`)}
          </button>
        ))}
      </div>

      {/* Both panels stay mounted, so switching tabs never loses a picked folder or a typed phrase. */}
      <div role="tabpanel" id="mt-tabpanel-decrypt" aria-labelledby="mt-tab-decrypt" hidden={tab !== 'decrypt'}>
        <DecryptPanel />
      </div>
      <div role="tabpanel" id="mt-tabpanel-generate" aria-labelledby="mt-tab-generate" hidden={tab !== 'generate'}>
        <GeneratePanel seed={seed} />
      </div>
      <div role="tabpanel" id="mt-tabpanel-publicKey" aria-labelledby="mt-tab-publicKey" hidden={tab !== 'publicKey'}>
        <PublicKeyPanel />
      </div>
    </main>
  );
}
