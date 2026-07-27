// The single source for every colour used in notification emails, and the one
// place a self-hosted instance re-themes them.
//
// Every value below is the resolved value of a Cunningham design token (named per
// line). Ideally they would be read live from the token values Cunningham exports
// in JS (`defaultTokens` in `@gouvfr-lasuite/cunningham-react`), but that entry
// point cannot be imported server-side: it is the same bundle as the React
// components and runs browser APIs (document.*) at import (still true in 4.4.0,
// checked; there is no tokens-only subpath export). And email clients cannot read
// CSS custom properties anyway, so a colour must reach the mail as a literal.
// Hence literals here, mirroring the tokens by hand.
//
// These are the DEFAULTS. esbuild bundles and minifies this file into the server
// executable, so they cannot be edited in a built image. Instead a self-hosted
// instance re-themes without rebuilding by providing a small JSON override file
// (EMAIL_PALETTE_PATH), read at startup and applied over these values via
// `applyEmailPaletteOverride` (see the server-side loader in `mailer.ts`). This
// module stays browser-safe (no fs) so Storybook can import it and keep the
// defaults. Every consumer reads `emailPalette.*` (or the lazy style getters) at
// render time, so an override applied before the first email render takes effect.
export type EmailPalette = {
  brandPrimary: string;
  onBrand: string;
  brandPrimaryDark: string;
  lightBody: string;
  lightCard: string;
  darkBody: string;
  darkCard: string;
  bodyTextLight: string;
  bodyTextDark: string;
  headingDark: string;
  footerText: string;
  dividerLight: string;
  dividerDark: string;
  fontFamily: string;
};

export const emailPalette: EmailPalette = {
  // Brand.
  brandPrimary: '#1167d4', // colors.brand-550 = background--semantic--brand--primary
  onBrand: '#eaf1fb', // colors.brand-050 = content--semantic--brand--on-brand
  brandPrimaryDark: '#5693e0', // colors.brand-400 — a lighter blue used for LINKS on the dark body (not the button)

  // The surrounding body and the content card, per theme. The card stays one shade
  // lighter than the body in both, so the layout reads the same way light or dark.
  lightBody: '#f7f8f8', // colors.gray-025 (background.surface.tertiary, light)
  lightCard: '#ffffff', // colors.gray-000 (background.surface.primary, light)
  darkBody: '#1b1c1d', // colors.gray-900
  darkCard: '#252627', // colors.gray-850 (background.surface.secondary, dark)

  // Text.
  bodyTextLight: '#3a3b3e', // colors.gray-750
  bodyTextDark: '#d2d4d8', // colors.gray-150
  headingDark: '#ffffff', // colors.gray-000
  footerText: '#686b6f', // colors.gray-550 (content.semantic.neutral.secondary)

  // Lines (divider / hr).
  dividerLight: '#e1e2e5', // colors.gray-100
  dividerDark: '#3a3b3e', // colors.gray-750

  fontFamily: 'Inter, Helvetica, Arial, sans-serif',
};

// Patches the palette in place from an instance override. Only known keys are
// applied (an unknown key is a typo in the override file, so it is reported rather
// than silently ignored). Values are taken as-is: any string a mail client accepts
// as a colour is valid, so validating the format here would only reject legitimate
// notations without adding safety.
export function applyEmailPaletteOverride(override: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(override)) {
    if (!(key in emailPalette)) {
      console.warn(`Ignoring unknown email palette key "${key}" from the override`);
      continue;
    }

    if (typeof value !== 'string') {
      console.warn(`Ignoring email palette key "${key}": expected a colour string, got ${typeof value}`);
      continue;
    }

    emailPalette[key as keyof EmailPalette] = value;
  }
}
