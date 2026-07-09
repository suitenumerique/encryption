import type { CSSProperties } from 'react';

import { normalizeDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';

/**
 * A decimal safety fingerprint shown as two harmonized lines of four 5-digit
 * groups (8 groups = 40 digits), so it never wraps unevenly (e.g. 6 + 2). Used
 * everywhere a fingerprint is DISPLAYED (read out loud, compared side by side);
 * the confirm-to-delete text INPUT keeps its plain single-line form.
 */
export function FingerprintDisplay({ fingerprint, style }: { fingerprint: string; style?: CSSProperties }) {
  const groups = normalizeDecimalFingerprint(fingerprint).match(/\d{5}/g) ?? [];
  const text = `${groups.slice(0, 4).join(' ')}\n${groups.slice(4, 8).join(' ')}`;

  return <span style={{ fontFamily: 'monospace', letterSpacing: '0.05em', userSelect: 'all', whiteSpace: 'pre', ...style }}>{text}</span>;
}
