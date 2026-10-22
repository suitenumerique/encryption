import { useCallback, useEffect, useRef, useState } from 'react';

import type { IdTokenSet } from '@encryption/src/ui/auth/login';

/**
 * Where a step-up (RFC 9470) stands for the screen that needed it:
 * - `idle`: nothing asked.
 * - `required`: the server refused a sensitive action; the user is offered to
 *   confirm their identity with a second factor.
 * - `no_second_factor`: a new ID token arrived WITHOUT one: the provider (or
 *   the user's account there) offers none, which only the user can enable.
 */
export type StepUpState = 'idle' | 'required' | 'no_second_factor';

/**
 * Step-up banner state. `markStepUpRequired` snapshots the ID token active at
 * the moment the server refused; the next DIFFERENT one (once authentication
 * is no longer in flight) settles the outcome: with a second factor, the
 * banner clears and `onConfirmed` runs (the screen retries its action).
 */
export function useStepUp(currentIdTokenSet: IdTokenSet | null, isAuthenticating: boolean, onConfirmed?: () => void) {
  const [state, setState] = useState<StepUpState>('idle');
  const [refusedIdToken, setRefusedIdToken] = useState<string | null>(null);
  const currentIdToken = currentIdTokenSet?.idToken ?? null;
  const onConfirmedRef = useRef(onConfirmed);

  useEffect(() => {
    onConfirmedRef.current = onConfirmed;
  }, [onConfirmed]);

  const markStepUpRequired = useCallback(() => {
    setRefusedIdToken(currentIdToken);
    setState('required');
  }, [currentIdToken]);

  const clearStepUp = useCallback(() => {
    setState('idle');
    setRefusedIdToken(null);
  }, []);

  useEffect(() => {
    if (state !== 'required' && state !== 'no_second_factor') return;
    if (isAuthenticating || !currentIdTokenSet || currentIdTokenSet.idToken === refusedIdToken) return;

    if (currentIdTokenSet.secondFactor) {
      setRefusedIdToken(null);
      setState('idle');
      onConfirmedRef.current?.();
    } else {
      setRefusedIdToken(currentIdTokenSet.idToken);
      setState('no_second_factor');
    }
  }, [state, isAuthenticating, currentIdTokenSet, refusedIdToken]);

  return { stepUpState: state, markStepUpRequired, clearStepUp };
}
