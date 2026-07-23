import { waitFor, within } from '@storybook/test';

export async function playFindMain(parentElement: HTMLElement): Promise<HTMLElement> {
  return await within(parentElement).findByRole('main');
}

export async function playFindForm(parentElement: HTMLElement): Promise<HTMLElement> {
  return await within(parentElement).findByRole('form');
}

export async function playFindButton(parentElement: HTMLElement, name: string | RegExp): Promise<HTMLElement> {
  return await within(parentElement).findByRole('button', { name });
}

export async function playFindDialog(parentElement: HTMLElement): Promise<HTMLElement> {
  return await within(parentElement).findByRole('dialog');
}

/**
 * Cunningham's <Alert> renders a plain `<div class="c__alert">` with NO
 * `role="alert"` (only its Toast carries that role), so `findByRole('alert')`
 * never matches one. The class is the reliable selector, and passing `text`
 * additionally proves WHICH message is shown rather than just "an alert exists".
 */
export async function playFindAlert(parentElement: HTMLElement, text?: string | RegExp, options?: { timeout?: number }): Promise<HTMLElement> {
  if (text !== undefined) {
    const node = await within(parentElement).findByText(text, undefined, options);
    const alert = node.closest('.c__alert');

    if (!alert) {
      throw new Error(`Found "${String(text)}" but it is not rendered inside an alert`);
    }

    return alert as HTMLElement;
  }

  return await waitFor(() => {
    const alert = parentElement.querySelector('.c__alert');

    if (!alert) {
      throw new Error('Unable to find an alert (.c__alert)');
    }

    return alert as HTMLElement;
  }, options);
}

export async function playFindHeading(parentElement: HTMLElement, name: string | RegExp): Promise<HTMLElement> {
  return await within(parentElement).findByRole('heading', { name });
}
