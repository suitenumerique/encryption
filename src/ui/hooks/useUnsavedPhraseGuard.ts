import { useEffect } from 'react';

/**
 * Warn before a tab reload/close would discard a recovery phrase the user has
 * seen but not yet confirmed (onboarding backup step, change-phrase backup step).
 * It cannot catch the parent product removing the iframe node (no unload fires).
 *
 * A Vite HMR full-reload in development is exempt: Vite dispatches
 * `vite:beforeFullReload` right before calling `location.reload()`, so without
 * this the native "Reload website?" dialog would pop on every code change while
 * the backup screen is open. The guard still fires for a genuine user
 * reload/close in dev, so it stays testable.
 */
export function useUnsavedPhraseGuard(active: boolean): void {
  useEffect(() => {
    if (!active) return;

    let hmrReloading = false;

    const handler = (e: BeforeUnloadEvent) => {
      if (hmrReloading) return;
      e.preventDefault();
      e.returnValue = '';
    };

    window.addEventListener('beforeunload', handler);

    const hot = import.meta.hot;
    const onFullReload = () => {
      hmrReloading = true;
    };
    hot?.on('vite:beforeFullReload', onFullReload);

    return () => {
      window.removeEventListener('beforeunload', handler);
      hot?.off('vite:beforeFullReload', onFullReload);
    };
  }, [active]);
}
