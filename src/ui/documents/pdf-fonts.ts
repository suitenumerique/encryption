import { Font } from '@react-pdf/renderer';

import { runtimeConfig } from '@encryption/src/ui/runtime-config';

// react-pdf ships NO custom fonts, but it DOES provide the standard PDF fonts, so
// the default (`Helvetica`) embeds no file and needs no download. Marianne is
// reserved for the French State, so it is NOT the default: a deployment entitled
// to it (or wanting its own brand font) sets the BRAND_FONT env, which the server
// injects as `brandFont` in the runtime config, and we register it here. See
// src/shared/brand-font.ts. `RECOVERY_KIT_FONT_FAMILY` is what the doc styles use.
const brandFont = runtimeConfig.brandFont;

export const RECOVERY_KIT_FONT_FAMILY = brandFont?.family ?? 'Helvetica';

if (brandFont) {
  const base = typeof window !== 'undefined' ? window.location.origin : '';
  const url = (src: string): string => (/^https?:\/\//.test(src) ? src : `${base}${src}`);

  // No fontWeight on the regular entry makes it the fallback for any unmatched weight.
  const fonts: { src: string; fontWeight?: number }[] = [{ src: url(brandFont.regular) }];
  if (brandFont.medium) fonts.push({ src: url(brandFont.medium), fontWeight: 500 });
  if (brandFont.bold) fonts.push({ src: url(brandFont.bold), fontWeight: 700 });

  Font.register({ family: brandFont.family, fonts });
}

// Recovery phrases are exact word lists: hyphenating a word that wraps would
// insert a "-" into it, so hyphenation is disabled document-wide.
Font.registerHyphenationCallback((word) => [word]);
