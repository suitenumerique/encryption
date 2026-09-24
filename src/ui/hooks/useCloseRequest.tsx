import { type ReactNode, createContext, useCallback, useContext, useEffect, useRef } from 'react';

/**
 * A screen may hold a guard: when the product's close control is used, the
 * guard runs instead of closing (the backup step asks "cancel the setup?").
 * The guard returns true when it handled the request itself.
 */
type CloseGuard = () => boolean;

interface CloseRequestContextValue {
  /** Register the guard for the mounted screen; returns the unregister function. */
  register: (guard: CloseGuard) => () => void;
}

const CloseRequestContext = createContext<CloseRequestContextValue | null>(null);

/**
 * Routes the product's close requests (MSG_INTERFACE_REQUEST_CLOSE, relayed by
 * the parent-messages hook as an incrementing counter) to the current screen's
 * guard, falling back to `onClose` when no guard is mounted or when the guard
 * lets the request through.
 */
export function CloseRequestProvider({ requests, onClose, children }: { requests: number; onClose: () => void; children: ReactNode }) {
  const guardRef = useRef<CloseGuard | null>(null);
  const seenRef = useRef(requests);

  const register = useCallback((guard: CloseGuard) => {
    guardRef.current = guard;

    return () => {
      if (guardRef.current === guard) guardRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (requests === seenRef.current) return;

    seenRef.current = requests;

    if (guardRef.current?.()) return;

    onClose();
  }, [requests, onClose]);

  return <CloseRequestContext.Provider value={{ register }}>{children}</CloseRequestContext.Provider>;
}

/**
 * Intercept the product's close control while `active`. Outside a provider
 * (stories, tests) it is a no-op.
 */
export function useCloseGuard(active: boolean, guard: () => void): void {
  const ctx = useContext(CloseRequestContext);
  const guardRef = useRef(guard);

  useEffect(() => {
    guardRef.current = guard;
  });

  useEffect(() => {
    if (!ctx || !active) return;

    return ctx.register(() => {
      guardRef.current();

      return true;
    });
  }, [ctx, active]);
}
