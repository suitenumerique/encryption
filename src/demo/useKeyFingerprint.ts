import { useEffect, useState } from 'react';

import { computeKeyFingerprint, formatFingerprint } from '@encryption/src/crypto/fingerprint';

/**
 * Computes a fingerprint of a base64-encoded public key.
 * Returns a formatted hex string like "A1B2 C3D4 E5F6 7890", or null.
 * Adapted from docs/src/features/docs/doc-collaboration/hook/useKeyFingerprint.tsx
 */
export function useKeyFingerprint(base64Key: string | null | undefined): string | null {
  const [fingerprint, setFingerprint] = useState<string | null>(null);

  useEffect(() => {
    if (!base64Key) {
      setFingerprint(null);

      return;
    }

    let cancelled = false;

    computeKeyFingerprint(base64Key).then((fp) => {
      if (!cancelled) {
        setFingerprint(formatFingerprint(fp));
      }
    });

    return () => {
      cancelled = true;
    };
  }, [base64Key]);

  return fingerprint;
}
