import { useEffect, useState } from 'react';

import { MSG_INTERFACE_CONTEXT, MSG_INTERFACE_REQUEST_CONTEXT } from '@encryption/src/shared/constants';

interface ParentContext {
  /** suiteUserId from the parent product (the cross-product user identifier) */
  suiteUserId: string | null;
  /** Origin of the parent frame that sent the context message */
  parentOrigin: string | null;
}

/**
 * Listens for context messages from the parent frame.
 * The parent product sends { type: 'interface:context', suiteUserId }
 * when opening the interface iframe. The interface handles its own
 * authentication via OIDC — the parent does not send tokens.
 */
export function useParentMessages(): ParentContext {
  const [context, setContext] = useState<ParentContext>({
    suiteUserId: null,
    parentOrigin: null,
  });

  useEffect(() => {
    const handler = (event: MessageEvent) => {
      if (!event.data || typeof event.data !== 'object' || event.data.type !== MSG_INTERFACE_CONTEXT) {
        return;
      }

      setContext({
        suiteUserId: event.data.suiteUserId ?? null,
        parentOrigin: event.origin,
      });
    };

    window.addEventListener('message', handler);

    // Request context from the parent — handshake ensures
    // the context is received regardless of load timing
    if (window.parent !== window) {
      window.parent.postMessage({ type: MSG_INTERFACE_REQUEST_CONTEXT }, '*');
    }

    return () => window.removeEventListener('message', handler);
  }, []);

  return context;
}
