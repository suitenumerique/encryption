// The single source for every colour used in notification emails, and the one
// place a self-hosted instance re-themes them.
//
// Every default is read from the design system's resolved token values
// (`@gouvfr-lasuite/ui-tokens`, the tokens-only package without React, safe to
// bundle into the server), so an upgrade of the design system reaches the emails
// too. They are copied as literals because email clients cannot read CSS custom
// properties: a colour must reach the mail as a value. Lowercased so the rendered
// HTML keeps the notation the templates and overrides use.
//
// These are the DEFAULTS. esbuild bundles this file into the server executable,
// so they cannot be edited in a built image. Instead a self-hosted instance
// re-themes without rebuilding by providing a small JSON override file
// (EMAIL_PALETTE_PATH), read at startup and applied over these values via
// `applyEmailPaletteOverride` (see the server-side loader in `mailer.ts`). This
// module stays browser-safe (no fs) so Storybook can import it and keep the
// defaults. Every consumer reads `emailPalette.*` (or the lazy style getters) at
// render time, so an override applied before the first email render takes effect.
import { defaultThemes } from '@gouvfr-lasuite/ui-tokens';

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

const light = defaultThemes.default;
const dark = defaultThemes.dark;
const gray = light.globals.colors;

export const emailPalette: EmailPalette = {
  // Brand.
  brandPrimary: light.contextuals.background.semantic.brand.primary.toLowerCase(),
  onBrand: light.contextuals.content.semantic.brand['on-brand'].toLowerCase(),
  // A lighter blue for LINKS on the dark body (not the button).
  brandPrimaryDark: gray['brand-400'].toLowerCase(),

  // The surrounding body and the content card, per theme. The card stays one shade
  // lighter than the body in both, so the layout reads the same way light or dark.
  lightBody: light.contextuals.background.surface.tertiary.toLowerCase(),
  lightCard: light.contextuals.background.surface.primary.toLowerCase(),
  darkBody: dark.contextuals.background.surface.tertiary.toLowerCase(),
  darkCard: dark.contextuals.background.surface.secondary.toLowerCase(),

  // Text.
  bodyTextLight: gray['gray-750'].toLowerCase(),
  bodyTextDark: gray['gray-150'].toLowerCase(),
  headingDark: gray['gray-000'].toLowerCase(),
  footerText: gray['gray-550'].toLowerCase(),

  // Lines (divider / hr).
  dividerLight: light.contextuals.border.surface.primary.toLowerCase(),
  dividerDark: dark.contextuals.border.surface.primary.toLowerCase(),

  // Web-safe on purpose: an email client loads no web font, and the design
  // system's own families (Roboto Flex, Marianne) are not installed on readers' machines.
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
