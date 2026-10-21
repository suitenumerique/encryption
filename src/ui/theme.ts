// Theme names a product may pass (SDK `theme` option, `#theme=` hash) mapped to
// the theme classes the design system ships (`cunningham-theme--<name>`). The
// products' own token sets name the French government theme `dsfr`, the design
// system names it `dsfr-light`: without the alias the interface would silently
// fall back to the default theme, its font included.
const THEME_ALIASES: Record<string, string> = {
  light: 'default',
  dsfr: 'dsfr-light',
  anct: 'anct-light',
};

export function resolveThemeName(name: string | null | undefined): string {
  if (!name) return 'default';

  return THEME_ALIASES[name] ?? name;
}
