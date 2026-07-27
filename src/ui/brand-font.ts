import { type BrandFont, brandFontFaceCss } from '@encryption/src/shared/brand-font';

// The interface's default open font, matching the rest of La Suite: Inter (loaded
// via `@fontsource-variable/inter` in index.tsx), then Cunningham's own default,
// then the system sans. This overrides Cunningham's bare Roboto-Flex token so the
// UI actually renders in a loaded font rather than the OS default.
const DEFAULT_UI_FONT_STACK = 'Inter, "Roboto Flex Variable", sans-serif';

/**
 * Point Cunningham's base + accent font tokens at the UI font. A deployment that
 * set BRAND_FONT gets that font PREPENDED (and loaded via @font-face), so the
 * whole UI uses the same brand font as the emails and the Recovery Kit PDF, with
 * Inter as the loaded fallback. Marianne stays opt-in.
 */
export function applyBrandFont(): void {
  const brandFont = (window as unknown as { __ENCRYPTION_CONFIG__?: { brandFont?: BrandFont } }).__ENCRYPTION_CONFIG__?.brandFont;

  const stack = brandFont ? `"${brandFont.family}", ${DEFAULT_UI_FONT_STACK}` : DEFAULT_UI_FONT_STACK;
  const faces = brandFont ? brandFontFaceCss(brandFont, window.location.origin) : '';

  const style = document.createElement('style');
  style.textContent = `${faces}:root{--c--globals--font--families--base:${stack};--c--globals--font--families--accent:${stack};}`;

  document.head.appendChild(style);
}
