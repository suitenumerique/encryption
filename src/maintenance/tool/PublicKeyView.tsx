import { useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';

import { formatDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

/** A maintenance public key as the deployment's team needs it: to read, copy or download, with its fingerprint. */
export function PublicKeyView({ title, publicKey, fingerprint }: { title: string; publicKey: string; fingerprint: string }) {
  const { t } = useTranslation('common');
  const url = useMemo(() => URL.createObjectURL(new Blob([`${publicKey}\n`], { type: 'text/plain' })), [publicKey]);

  useEffect(() => () => URL.revokeObjectURL(url), [url]);

  return (
    <section className="mt-step">
      <h2>{title}</h2>
      {/* Selected whole on the first click: it is copied as one value, never in part. */}
      <textarea
        className="mt-public-key"
        readOnly
        rows={6}
        value={publicKey}
        aria-label={title}
        onFocus={(event) => event.currentTarget.select()}
        onClick={(event) => event.currentTarget.select()}
      />
      <a className="mt-button" href={url} download="maintenance-public-key.txt">
        {t('maintenanceTool.generate.downloadPublicKey')}
      </a>
      <p className="mt-status">
        {t('maintenanceTool.generate.fingerprint')} <code className="mt-fingerprint">{formatDecimalFingerprint(fingerprint)}</code>
      </p>
    </section>
  );
}
