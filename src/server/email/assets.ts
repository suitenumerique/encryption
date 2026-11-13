// Absolute base for assets referenced from emails (the logo). Real mail clients
// need an absolute URL, so the mailer sets this from the interface URL at startup.
// It stays empty in Storybook, where a root-relative path resolves against the
// origin rendering the preview (which serves /public-assets via a static dir).
let base = '';

export function setEmailAssetBaseUrl(url: string | undefined): void {
  base = (url ?? '').replace(/\/+$/, '');
}

export function emailLogoUrl(file: 'logo.png' | 'logo-dark.png'): string {
  return `${base}/public-assets/${file}`;
}

/** Absolute base the email uses to resolve root-relative asset URLs (e.g. brand-font woff). */
export function emailAssetBaseUrl(): string {
  return base;
}
