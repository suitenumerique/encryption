import { within } from '@storybook/test';

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

export async function playFindAlert(parentElement: HTMLElement): Promise<HTMLElement> {
  return await within(parentElement).findByRole('alert');
}

export async function playFindHeading(parentElement: HTMLElement, name: string | RegExp): Promise<HTMLElement> {
  return await within(parentElement).findByRole('heading', { name });
}
