import { brandFontFaceCss } from '@encryption/src/shared/brand-font';
import { runtimeConfig } from '@encryption/src/ui/runtime-config';

// The fallbacks after a brand font: the design system's own families (Marianne
// for the DSFR and ANCT themes, loaded in index.tsx), then Inter, also loaded.
const FALLBACK_FONT_STACK = 'Marianne, Inter, "Roboto Flex Variable", sans-serif';

/**
 * Without BRAND_FONT the interface keeps the font of the theme the product
 * passed, like the product itself. A deployment that set BRAND_FONT gets that
 * font in front of every theme's (and loaded via @font-face), so the whole UI,
 * the printed Recovery Kit included, uses the same brand font as the emails.
 */
export function applyBrandFont(): void {
  const brandFont = runtimeConfig.brandFont;

  if (!brandFont) return;

  const stack = `"${brandFont.family}", ${FALLBACK_FONT_STACK}`;
  const style = document.createElement('style');
  style.textContent = `${brandFontFaceCss(brandFont, window.location.origin)}:root,[class*="cunningham-theme--"]{--c--globals--font--families--base:${stack};--c--globals--font--families--accent:${stack};}`;

  document.head.appendChild(style);
}
