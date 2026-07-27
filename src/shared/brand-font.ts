// The single brand font for the whole product: the emails, the Recovery Kit PDF
// and the interface UI all use the same one. It is NOT known at build time (one
// Docker image serves every deployment), so it is configured at runtime through
// the BRAND_FONT env (JSON: a family name + per-weight woff URLs). Unset = each
// surface's generic fallback, no embedded/loaded custom font. Marianne is reserved
// for the French State, so it is never the default: an entitled deployment opts in
// by pointing BRAND_FONT at woff files it serves.
//
// The server reads BRAND_FONT once and (1) stashes it here for email rendering and
// (2) injects it into the interface runtime config (window.__ENCRYPTION_CONFIG__)
// for the PDF and the UI.

export interface BrandFont {
  family: string;
  regular: string;
  medium?: string;
  bold?: string;
}

/** Parse the BRAND_FONT env; a malformed value falls back to the default. */
export function parseBrandFont(raw: string | undefined): BrandFont | undefined {
  if (!raw) return undefined;

  try {
    const value = JSON.parse(raw) as Partial<BrandFont>;

    if (typeof value.family === 'string' && typeof value.regular === 'string') {
      return {
        family: value.family,
        regular: value.regular,
        medium: typeof value.medium === 'string' ? value.medium : undefined,
        bold: typeof value.bold === 'string' ? value.bold : undefined,
      };
    }
  } catch {
    // Malformed override: fall back to the built-in default rather than crash.
  }

  return undefined;
}

/**
 * `@font-face` CSS so a surface can actually LOAD the brand font (not just name it):
 * needed for the UI and for email clients that support web fonts (a reader without
 * the font installed otherwise falls back to the family stack). Relative URLs are
 * resolved against `baseUrl` (the interface origin for the UI; the absolute UI URL
 * for emails, which mail clients cannot resolve relatively). Empty when unset.
 */
export function brandFontFaceCss(font: BrandFont | undefined, baseUrl: string): string {
  if (!font) return '';

  const url = (src: string): string => (/^https?:\/\//.test(src) ? src : `${baseUrl}${src}`);
  const face = (src: string | undefined, weight: number): string =>
    src ? `@font-face{font-family:"${font.family}";src:url("${url(src)}") format("woff");font-weight:${weight};font-display:swap;}` : '';

  return face(font.regular, 400) + face(font.medium, 500) + face(font.bold, 700);
}

// Server-only holder: emails render with no window and no env access at call time,
// so the brand font resolved once at startup (mailer.ts) is stashed here for the
// email layout. The interface reads the same value from the injected runtime config
// instead, and Storybook never sets it, so emails fall back to the generic stack.
let serverBrandFont: BrandFont | undefined;

export function setServerBrandFont(font: BrandFont | undefined): void {
  serverBrandFont = font;
}

export function getServerBrandFont(): BrandFont | undefined {
  return serverBrandFont;
}
