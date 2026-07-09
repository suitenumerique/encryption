import { useCallback, useEffect, useState } from 'react';

/**
 * Session-expired banner state, shared by onboarding, settings and device
 * approval. `markSessionExpired` snapshots the access token active at the
 * moment the expiry was detected; once the Reconnect flow produces a DIFFERENT
 * token (and authentication is no longer in flight), the banner auto-clears.
 */
export function useSessionExpired(currentAccessToken: string | null | undefined, isAuthenticating: boolean) {
  const [sessionExpired, setSessionExpired] = useState(false);
  const [expiredAtToken, setExpiredAtToken] = useState<string | null>(null);

  const markSessionExpired = useCallback(() => {
    setExpiredAtToken(currentAccessToken ?? null);
    setSessionExpired(true);
  }, [currentAccessToken]);

  const clearSessionExpired = useCallback(() => {
    setSessionExpired(false);
    setExpiredAtToken(null);
  }, []);

  useEffect(() => {
    if (sessionExpired && !isAuthenticating && currentAccessToken && currentAccessToken !== expiredAtToken) {
      setSessionExpired(false);
      setExpiredAtToken(null);
    }
  }, [sessionExpired, isAuthenticating, currentAccessToken, expiredAtToken]);

  return { sessionExpired, markSessionExpired, clearSessionExpired };
}
