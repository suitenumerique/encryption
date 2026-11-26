import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';

import { mnemonicLanguageForLocale } from '@encryption/src/crypto/mnemonic';
import { enrollCouncilEscrow, fetchCouncilForMe } from '@encryption/src/ui/api/council-client';
import { withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { checkedRecently, rememberCheck, renewCouncilEscrowIfDue } from '@encryption/src/ui/council-renewal';
import { useCouncilVault } from '@encryption/src/ui/hooks/useCouncilVault';

/**
 * At most once a day per user, on an interface visit, renew the user's council escrow when a custodian of
 * its secret has left. Best effort and silent: a request in progress or a head
 * that changed meanwhile (409) waits for the next visit, and the settings show
 * any escrow that does not verify.
 */
export function useCouncilRenewal(getIdToken: () => Promise<string | null>, userId: string | null, enabled: boolean): void {
  const { i18n } = useTranslation('common');
  const vault = useCouncilVault();
  const done = useRef(false);

  useEffect(() => {
    if (!enabled || !userId || done.current) return;
    done.current = true;

    const storage = browserStorage();
    if (checkedRecently(userId, Date.now(), storage)) return;

    renewCouncilEscrowIfDue({
      fetchForMe: () => withFreshIdToken(getIdToken, fetchCouncilForMe),
      checkEscrow: vault.checkEscrow,
      createEscrow: vault.createEscrow,
      enroll: (body) => withFreshIdToken(getIdToken, (idToken) => enrollCouncilEscrow(idToken, vault.sign, body)),
      lang: mnemonicLanguageForLocale(i18n.language),
    })
      // Remembered only once the check went through: a failure tries again next visit.
      .then(() => rememberCheck(userId, Date.now(), storage))
      .catch((err: unknown) => {
        console.warn('[encryption-ui] Council escrow renewal skipped:', err);
      });
  }, [enabled, userId, getIdToken, vault, i18n.language]);
}

function browserStorage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}
