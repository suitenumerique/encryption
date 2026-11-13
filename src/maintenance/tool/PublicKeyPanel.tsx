import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { exportMaintenancePublicKey } from '@encryption/src/crypto/maintenance-escrow';
import { PhraseInput, type PhraseKey } from '@encryption/src/maintenance/tool/PhraseInput';
import { PublicKeyView } from '@encryption/src/maintenance/tool/PublicKeyView';

/** The public key of a phrase already held: derived from it, as at generation. */
export function PublicKeyPanel() {
  const { t } = useTranslation('common');
  const [key, setKey] = useState<PhraseKey | null>(null);

  return (
    <div className="mt-panel">
      <p className="mt-help">{t('maintenanceTool.publicKey.help')}</p>
      <PhraseInput idPrefix="mt-public-key" onKey={setKey} />
      {key && (
        <PublicKeyView
          title={t('maintenanceTool.publicKey.title')}
          publicKey={exportMaintenancePublicKey(key.publicKey)}
          fingerprint={key.fingerprint}
        />
      )}
    </div>
  );
}
