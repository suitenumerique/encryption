import { CunninghamProvider } from '@gouvfr-lasuite/ui-components';
// Only for the Material Icons ligatures that design system parts draw
// themselves and take no icon prop to replace: the QuickSearch input
// ("search"), ShareModal's rows, link settings and "load more"
// ("add", "arrow_drop_down", "arrow_downward"), ShareModalCopyLinkFooter
// ("link") and InvitationUserSelectorList ("close"). The patterns' own icons
// are the design system's SVG icons.
import '@gouvfr-lasuite/ui-components/fonts/material-icons';
import '@gouvfr-lasuite/ui-components/style';
import { type ReactNode, createContext, useContext, useMemo } from 'react';

import '@encryption/src/product-patterns/product-patterns.css';
import { type PatternLocale, type PatternTranslate, createTranslate } from '@encryption/src/product-patterns/strings';

const PatternTranslateContext = createContext<PatternTranslate>(createTranslate('fr'));

export function usePatternTranslate(): PatternTranslate {
  return useContext(PatternTranslateContext);
}

const CUNNINGHAM_LOCALES: Record<PatternLocale, string> = { en: 'en-US', fr: 'fr-FR' };

// The products render inside the design system provider, which carries the
// share modal's own strings ("N members", "Add", ...) in the matching locale.
// The theme follows the one Storybook put on the root element, since the
// provider rewrites that class on mount.
export function PatternProvider({ locale, children }: { locale: PatternLocale; children: ReactNode }) {
  const translate = useMemo(() => createTranslate(locale), [locale]);
  const theme = document.documentElement.classList.contains('cunningham-theme--dark') ? 'dark' : 'default';

  return (
    <CunninghamProvider currentLocale={CUNNINGHAM_LOCALES[locale]} theme={theme}>
      <PatternTranslateContext.Provider value={translate}>{children}</PatternTranslateContext.Provider>
    </CunninghamProvider>
  );
}
