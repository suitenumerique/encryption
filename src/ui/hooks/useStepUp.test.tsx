/**
 * @vitest-environment jsdom
 */
import { act, createElement, useEffect } from 'react';
import { type Root, createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { IdTokenSet } from '@encryption/src/ui/auth/login';
import { type StepUpState, useStepUp } from '@encryption/src/ui/hooks/useStepUp';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const idTokenSet = (idToken: string, secondFactor: boolean): IdTokenSet => ({
  idToken,
  idTokenExpiresAt: Date.now() + 3_600_000,
  sub: 'user-42',
  userId: 'u',
  firstName: 'Alice',
  lastName: 'Martin',
  email: null,
  secondFactor,
});

let root: Root;
let latest: { stepUpState: StepUpState; markStepUpRequired: () => void };

function Probe(props: { idTokenSet: IdTokenSet | null; isAuthenticating: boolean; onConfirmed: () => void; report: (value: typeof latest) => void }) {
  const stepUp = useStepUp(props.idTokenSet, props.isAuthenticating, props.onConfirmed);

  useEffect(() => props.report(stepUp));

  return null;
}

function render(props: Omit<Parameters<typeof Probe>[0], 'report'>) {
  act(() =>
    root.render(
      createElement(Probe, {
        ...props,
        report: (value) => {
          latest = value;
        },
      })
    )
  );
}

beforeEach(() => {
  root = createRoot(document.createElement('div'));
});

afterEach(() => act(() => root.unmount()));

describe('useStepUp', () => {
  it('retries the action once a new ID token reports a second factor', () => {
    const onConfirmed = vi.fn();

    render({ idTokenSet: idTokenSet('password-login', false), isAuthenticating: false, onConfirmed });
    act(() => latest.markStepUpRequired());
    expect(latest.stepUpState).toBe('required');

    // The step-up tab is open: nothing settles yet.
    render({ idTokenSet: idTokenSet('password-login', false), isAuthenticating: true, onConfirmed });
    expect(latest.stepUpState).toBe('required');

    render({ idTokenSet: idTokenSet('fresh-mfa-login', true), isAuthenticating: false, onConfirmed });
    expect(latest.stepUpState).toBe('idle');
    expect(onConfirmed).toHaveBeenCalledTimes(1);
  });

  it('says so when the new ID token carries no second factor, and does not retry', () => {
    const onConfirmed = vi.fn();

    render({ idTokenSet: idTokenSet('password-login', false), isAuthenticating: false, onConfirmed });
    act(() => latest.markStepUpRequired());
    render({ idTokenSet: idTokenSet('still-password-login', false), isAuthenticating: false, onConfirmed });

    expect(latest.stepUpState).toBe('no_second_factor');
    expect(onConfirmed).not.toHaveBeenCalled();
  });

  it('ignores token changes when no step-up was asked', () => {
    const onConfirmed = vi.fn();

    render({ idTokenSet: idTokenSet('a', false), isAuthenticating: false, onConfirmed });
    render({ idTokenSet: idTokenSet('b', true), isAuthenticating: false, onConfirmed });

    expect(latest.stepUpState).toBe('idle');
    expect(onConfirmed).not.toHaveBeenCalled();
  });
});
