import { useTranslation } from 'react-i18next';

import { maintenanceFingerprintToKeyIdHex } from '@encryption/src/crypto/maintenance-escrow';
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

/** The 40 digits custodians compare with the server's startup log. */
export function Fingerprint({ fingerprint, help }: { fingerprint: string; help: string }) {
  const { t } = useTranslation('common');

  return (
    <ValueBlock label={t('maintenanceTool.fingerprintLabel')} value={formatDecimalFingerprint(fingerprint)} help={help} className="mt-fingerprint" />
  );
}

/** The same key's id in hexadecimal, which a product's export command filters the copies on. */
export function KeyId({ fingerprint }: { fingerprint: string }) {
  const { t } = useTranslation('common');

  return (
    <ValueBlock label={t('maintenanceTool.keyIdLabel')} value={maintenanceFingerprintToKeyIdHex(fingerprint)} help={t('maintenanceTool.keyIdHelp')} />
  );
}
