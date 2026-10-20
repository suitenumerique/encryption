import { useTranslation } from 'react-i18next';

import { formatDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

/** A value someone compares or copies: set apart, in large type, selected whole on a click. */
function ValueBlock({ label, value, help, className }: { label: string; value: string; help: string; className?: string }) {
  return (
    <div className="mt-value-block">
      <span className="mt-label">{label}</span>
      <code className={className ? `mt-value ${className}` : 'mt-value'}>{value}</code>
      <span className="mt-help">{help}</span>
    </div>
  );
}

/** The 40 digits custodians compare with the server's startup log, and name their key by when they ask for an export. */
export function Fingerprint({ fingerprint, help }: { fingerprint: string; help: string }) {
  const { t } = useTranslation('common');

  return (
    <ValueBlock label={t('maintenanceTool.fingerprintLabel')} value={formatDecimalFingerprint(fingerprint)} help={help} className="mt-fingerprint" />
  );
}
