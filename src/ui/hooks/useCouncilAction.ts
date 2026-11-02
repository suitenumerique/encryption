import { useCallback, useState } from 'react';

import { type CouncilAuthProps, useCouncilErrors } from '@encryption/src/ui/hooks/useCouncilErrors';

/**
 * A council screen's actions: one at a time, the banner cleared when one starts
 * and filled when it fails. `busy` names the running action (a request id, a
 * session id), so a list can show which row is working.
 */
export function useCouncilAction(auth: CouncilAuthProps) {
  const { banner, fail, clear } = useCouncilErrors(auth);
  const [busy, setBusy] = useState<string | null>(null);

  const run = useCallback(
    async (action: () => Promise<void>, key = 'action'): Promise<boolean> => {
      setBusy(key);
      clear();

      try {
        await action();

        return true;
      } catch (err) {
        fail(err);

        return false;
      } finally {
        setBusy(null);
      }
    },
    [fail, clear]
  );

  return { banner, fail, clear, busy, run };
}
