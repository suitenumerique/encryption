import { useEffect } from 'react';

/**
 * Keeps a story on its own canvas.
 *
 * A story renders one component in isolation, so anything that would navigate
 * the preview iframe (a link, a form submit) destroys the thing being
 * demonstrated: Storybook loses the story and you are left on a blank or
 * unrelated page. Both are intercepted in the capture phase and logged instead.
 *
 * `history.pushState` is deliberately NOT patched: the preview iframe uses it
 * for Storybook's own args/state sync, and overriding it breaks the toolbar.
 * In-app navigation reaches components as `on*` props, which are auto-stubbed as
 * logged actions (see generateMetaDefault), so it never runs in a story anyway.
 */
export function useNavigationGuard(): void {
  useEffect(() => {
    const onClick = (event: MouseEvent) => {
      const anchor = (event.target as HTMLElement | null)?.closest?.('a[href]');

      if (!anchor) {
        return;
      }

      const href = anchor.getAttribute('href') ?? '';

      // In-page anchors and explicit new tabs are harmless: they do not replace
      // the story. Downloads (RecoveryKitBackup builds a blob link) must pass too.
      if (href.startsWith('#') || anchor.getAttribute('target') === '_blank' || anchor.hasAttribute('download')) {
        return;
      }

      event.preventDefault();
      console.warn(`[storybook] navigation to "${href}" blocked: a story must stay on its own canvas`);
    };

    const onSubmit = (event: Event) => {
      event.preventDefault();
      console.warn('[storybook] form submit blocked: it would reload the preview and drop the story');
    };

    document.addEventListener('click', onClick, true);
    document.addEventListener('submit', onSubmit, true);

    return () => {
      document.removeEventListener('click', onClick, true);
      document.removeEventListener('submit', onSubmit, true);
    };
  }, []);
}
