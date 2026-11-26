import { useCallback, useEffect, useState } from 'react';

/**
 * Session-expired banner state, shared by onboarding, settings and device
 * approval. `markSessionExpired` snapshots the ID token active at the
 * moment the expiry was detected; once the Reconnect flow produces a DIFFERENT
 * token (and authentication is no longer in flight), the banner auto-clears.
 */
export function useSessionExpired(currentIdToken: string | null | undefined, isAuthenticating: boolean) {
  const [sessionExpired, setSessionExpired] = useState(false);
  const [expiredAtToken, setExpiredAtToken] = useState<string | null>(null);

  const markSessionExpired = useCallback(() => {
    setExpiredAtToken(currentIdToken ?? null);
    setSessionExpired(true);
  }, [currentIdToken]);

  const clearSessionExpired = useCallback(() => {
    setSessionExpired(false);
    setExpiredAtToken(null);
  }, []);

  useEffect(() => {
    if (sessionExpired && !isAuthenticating && currentIdToken && currentIdToken !== expiredAtToken) {
      setSessionExpired(false);
      setExpiredAtToken(null);
    }
  }, [sessionExpired, isAuthenticating, currentIdToken, expiredAtToken]);

  return { sessionExpired, markSessionExpired, clearSessionExpired };
}
