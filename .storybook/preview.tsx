import { CunninghamProvider } from '@gouvfr-lasuite/cunningham-react';
import '@gouvfr-lasuite/cunningham-react/icons';
import '@gouvfr-lasuite/cunningham-react/style';
import { addons } from '@storybook/preview-api';
import type { Preview } from '@storybook/react';
import { themes } from '@storybook/theming';
import { initialize, mswLoader } from 'msw-storybook-addon';
import React, { useEffect, useState } from 'react';
import { I18nextProvider } from 'react-i18next';

import { useNavigationGuard } from '@encryption/.storybook/navigation-guard';
import i18n from '@encryption/src/i18n';
import { DEFAULT_LOCALE } from '@encryption/src/shared/locale';
import type { EncryptionContextType } from '@encryption/src/ui/providers/EncryptionProvider';
import { defaultHandlers } from '@encryption/src/ui/testing/default-handlers';
import { MockEncryptionProvider } from '@encryption/src/ui/testing/mock-encryption';

const DARK_MODE_EVENT_NAME = 'DARK_MODE';

// Start the MSW worker once. Only warn on UNMOCKED /api calls (so a missing
// handler is visible) while staying silent for Storybook's own asset requests.
initialize({
  onUnhandledRequest(request, print) {
    if (new URL(request.url).pathname.startsWith('/api/')) {
      print.warning();
    }
  },
});

function readPersistedDarkMode(): boolean {
  try {
    const raw = window.localStorage.getItem('sb-addon-themes-3');

    return raw ? JSON.parse(raw).current === 'dark' : false;
  } catch {
    return false;
  }
}

function useStorybookDarkMode(): boolean {
  const [isDark, setIsDark] = useState(readPersistedDarkMode);

  useEffect(() => {
    const channel = addons.getChannel();

    const handler = (dark: boolean) => {
      setIsDark(dark);
    };

    channel.on(DARK_MODE_EVENT_NAME, handler);

    return () => {
      channel.off(DARK_MODE_EVENT_NAME, handler);
    };
  }, []);

  return isDark;
}

const preview: Preview = {
  loaders: [mswLoader],
  globalTypes: {
    locale: {
      description: 'Interface language',
      defaultValue: DEFAULT_LOCALE,
      toolbar: {
        icon: 'globe',
        items: [
          { value: 'fr', title: 'Français' },
          { value: 'en', title: 'English' },
        ],
        dynamicTitle: true,
      },
    },
  },
  parameters: {
    options: {
      storySort: {
        order: ['Docs', ['Architecture'], 'Preview', ['Pages', 'Modals', 'Layouts', 'Forms', 'Components', 'Emails', 'Documents']],
      },
    },
    backgrounds: {
      disable: true,
    },
    darkMode: {
      current: 'light',
      stylePreview: true,
      dark: { ...themes.dark },
      light: { ...themes.light },
    },
    msw: {
      handlers: defaultHandlers,
    },
  },
  decorators: [
    // Every interface component reads the vault through useEncryptionContext.
    // The real provider mounts a cross-origin iframe, which cannot work in
    // Storybook, so all stories get the stub. A story overrides individual
    // vault calls via `parameters.encryption`.
    (Story, context) => (
      <MockEncryptionProvider value={context.parameters.encryption as Partial<EncryptionContextType> | undefined}>
        <Story />
      </MockEncryptionProvider>
    ),
    (Story, context) => {
      useNavigationGuard();

      const locale = (context.globals.locale as string) ?? DEFAULT_LOCALE;

      // Synchronously before first paint, so a play() never observes the
      // previous language on the initial render.
      if (i18n.language !== locale) {
        void i18n.changeLanguage(locale);
      }

      const isDark = useStorybookDarkMode();
      const cunninghamTheme = isDark ? 'dark' : 'default';

      // Also update the root element so any raw CSS using Cunningham variables works
      useEffect(() => {
        document.documentElement.classList.toggle('cunningham-theme--dark', isDark);
        document.documentElement.classList.toggle('cunningham-theme--default', !isDark);
      }, [isDark]);

      // Fullscreen stories (a document PDF preview, an email, a docs page) only drop
      // the padding to go edge-to-edge; minHeight (not a fixed height) lets taller
      // content grow and scroll rather than being clipped.
      const isFullscreen = context.parameters.layout === 'fullscreen';

      return (
        <I18nextProvider i18n={i18n}>
          <CunninghamProvider theme={cunninghamTheme}>
            <div
              style={{
                background: 'var(--c--contextuals--background--surface--primary, #fff)',
                color: 'var(--c--contextuals--content--semantic--neutral--primary, #161616)',
                minHeight: '100%',
                ...(isFullscreen ? {} : { padding: 'var(--c--globals--spacings--4, 16px)' }),
              }}
            >
              <Story />
            </div>
          </CunninghamProvider>
        </I18nextProvider>
      );
    },
  ],
};

export default preview;
