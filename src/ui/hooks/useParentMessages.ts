import { useEffect, useState } from 'react';

import { MSG_INTERFACE_CONTEXT, MSG_INTERFACE_REQUEST_CONTEXT } from '@encryption/src/shared/constants';
import { type InterfaceContext, type RecipientLabel, interfaceContextSchema } from '@encryption/src/shared/schemas/interface-context';

interface ParentContext {
  /** suiteUserId from the parent product (the cross-product user identifier) */
  suiteUserId: string | null;
  /** Origin of the parent frame that sent the context message */
  parentOrigin: string | null;
  /**
   * The recipients to verify (userId → display label), set only when the SDK
   * opened the interface at /verify-recipients. Passed on the same context
   * channel so the handshake delivers it regardless of load timing.
   */
  verifyRecipients: Record<string, RecipientLabel> | null;
  /** The recipient to inspect and its label, set only when the SDK opened /recipient-profile. */
  recipientProfile: InterfaceContext['recipientProfile'] | null;
  /**
   * Actionable emergency-access state (pending invitations, running recovery
   * requests), set only when the SDK auto-opened the interface because of it.
   * The interface re-fetches the authoritative state; this only leads the prompt.
   */
  emergencyPending: InterfaceContext['emergencyPending'] | null;
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
    verifyRecipients: null,
    recipientProfile: null,
    emergencyPending: null,
  });

  useEffect(() => {
    const handler = (event: MessageEvent) => {
      if (!event.data || typeof event.data !== 'object' || event.data.type !== MSG_INTERFACE_CONTEXT) {
        return;
      }

      const parsed = interfaceContextSchema.safeParse(event.data);

      if (!parsed.success) {
        return;
      }

      setContext({
        suiteUserId: parsed.data.suiteUserId,
        parentOrigin: event.origin,
        verifyRecipients: parsed.data.verifyRecipients?.recipients ?? null,
        recipientProfile: parsed.data.recipientProfile ?? null,
        emergencyPending: parsed.data.emergencyPending ?? null,
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
