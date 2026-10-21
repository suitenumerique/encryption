import '@fontsource-variable/roboto-flex';
import { Button, CunninghamProvider } from '@gouvfr-lasuite/ui-components';
import '@gouvfr-lasuite/ui-components/fonts/marianne';
import { XMark } from '@gouvfr-lasuite/ui-components/icons';
import '@gouvfr-lasuite/ui-components/style';
import type { Preview } from '@storybook/react';
import { mswLoader } from 'msw-storybook-addon/csf3';
import { setupWorker } from 'msw/browser';
import { type ReactNode, useEffect, useState } from 'react';
import { I18nextProvider } from 'react-i18next';
import { addons } from 'storybook/preview-api';
import { themes } from 'storybook/theming';

import { installClock } from '@encryption/.storybook/clock';
import { useNavigationGuard } from '@encryption/.storybook/navigation-guard';
import i18n from '@encryption/src/i18n';
import { DEFAULT_LOCALE } from '@encryption/src/shared/locale';
import { CloseRequestProvider } from '@encryption/src/ui/hooks/useCloseRequest';
import { ModalSizeProvider } from '@encryption/src/ui/hooks/useModalSize';
import type { EncryptionContextType } from '@encryption/src/ui/providers/EncryptionProvider';
import { defaultHandlers } from '@encryption/src/ui/testing/default-handlers';
import { MockEncryptionProvider } from '@encryption/src/ui/testing/mock-encryption';
import { resolveThemeName } from '@encryption/src/ui/theme';

const DARK_MODE_EVENT_NAME = 'DARK_MODE';

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

function HostCloseControl({ children }: { children: ReactNode }) {
  const [requests, setRequests] = useState(0);

  return (
    <>
      {/* Where the interface's modal puts its cross (layout.module.css). */}
      <div style={{ position: 'absolute', top: 5, right: 5, zIndex: 1 }}>
        <Button
          icon={<XMark aria-hidden size={16} />}
          variant="tertiary"
          color="neutral"
          size="nano"
          aria-label="Close"
          onClick={() => setRequests((n) => n + 1)}
        />
      </div>
      <CloseRequestProvider requests={requests} onClose={() => console.log('host: interface closed')}>
        {children}
      </CloseRequestProvider>
    </>
  );
}

const preview: Preview = {
  // Start the MSW worker once, with the 501 safety net as its INITIAL handlers:
  // the addon prepends a story's own handlers at runtime, so they win, while the
  // net stays behind them for everything the story did not declare. (As a
  // `parameters.msw.handlers` array the net would be dropped, not merged, by any
  // story declaring its own array.) Only warn on UNMOCKED /api calls, and stay
  // silent for Storybook's own asset requests.
  loaders: [
    mswLoader(async () => {
      const worker = setupWorker(...defaultHandlers);

      await worker.start({
        quiet: true,
        onUnhandledRequest(request, print) {
          if (new URL(request.url).pathname.startsWith('/api/')) {
            print.warning();
          }
        },
      });

      return worker;
    }),
  ],
  // `parameters.date` pins "now" for a story that displays a date derived from it.
  beforeEach: ({ parameters }) => (parameters.date instanceof Date ? installClock(parameters.date) : undefined),
  globalTypes: {
    theme: {
      description: 'Design system theme the product passes',
      defaultValue: 'dsfr',
      toolbar: {
        icon: 'paintbrush',
        items: [
          { value: 'dsfr', title: 'DSFR' },
          { value: 'anct', title: 'ANCT' },
          // The design system's unbranded theme.
          { value: 'default', title: 'White label' },
        ],
        dynamicTitle: true,
      },
    },
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
      const brand = (context.globals.theme as string | undefined) ?? 'dsfr';
      const cunninghamTheme = resolveThemeName(brand === 'default' ? (isDark ? 'dark' : 'default') : `${brand}-${isDark ? 'dark' : 'light'}`);

      const hostModal = context.parameters.hostModal as boolean | 'medium' | 'card' | undefined;

      // Also update the root element so any raw CSS using Cunningham variables
      // works, and paint the page itself: a centered story covers only its own
      // box, and what shows around it is the preview document, which knows
      // nothing of the theme otherwise.
      useEffect(() => {
        const root = document.documentElement;
        root.classList.remove(...[...root.classList].filter((name) => name.startsWith('cunningham-theme--')));
        root.classList.add(`cunningham-theme--${cunninghamTheme}`);
        document.body.style.backgroundColor = hostModal
          ? 'var(--c--contextuals--background--surface--tertiary)'
          : 'var(--c--contextuals--background--surface--primary)';
      }, [cunninghamTheme, hostModal]);

      // Fullscreen stories (a printable document, an email, a docs page) only drop
      // the padding to go edge-to-edge; minHeight (not a fixed height) lets taller
      // content grow and scroll rather than being clipped.
      const isFullscreen = context.parameters.layout === 'fullscreen';

      // Interface screens are the content of the modal the interface draws over
      // the product (App.tsx). `hostModal` stands in for that chrome so a story
      // shows the screen at the width it really gets: the design system's small
      // modal (350px) or a wider one, which a screen asks for itself with
      // useModalSize as in the product (450px or 526px), or a story with
      // `'medium'` (450px). The cross
      // raises the same close request the modal's does, so a screen holding a
      // guard reacts like it does in the product, and an unguarded one only logs.
      // `'card'` is the width alone, for a component that lives inside a screen.
      return (
        <I18nextProvider i18n={i18n}>
          <CunninghamProvider theme={cunninghamTheme} currentLocale={locale === 'fr' ? 'fr-FR' : 'en-US'}>
            <div
              style={{
                background: hostModal
                  ? 'var(--c--contextuals--background--surface--tertiary, #f6f8f9)'
                  : 'var(--c--contextuals--background--surface--primary, #fff)',
                color: 'var(--c--contextuals--content--semantic--neutral--primary, #161616)',
                minHeight: '100%',
                ...(isFullscreen ? {} : { padding: 'var(--c--globals--spacings--4, 16px)' }),
              }}
            >
              {hostModal ? (
                <ModalSizeProvider>
                  {(size) => (
                    <div
                      style={{
                        position: 'relative',
                        width: size === 'large' ? 526 : hostModal === 'medium' || size === 'medium' ? 450 : 350,
                        maxWidth: '100%',
                        boxSizing: 'border-box',
                        padding: 'var(--c--components--modal--padding)',
                        borderRadius: 'var(--c--components--modal--border-radius)',
                        background: 'var(--c--components--modal--background-color)',
                        border: '1px solid var(--c--components--modal--border-color)',
                        boxShadow: 'var(--c--components--modal--box-shadow)',
                        fontFamily: 'var(--c--globals--font--families--base)',
                      }}
                    >
                      {hostModal === 'card' ? (
                        <Story />
                      ) : (
                        <HostCloseControl>
                          <Story />
                        </HostCloseControl>
                      )}
                    </div>
                  )}
                </ModalSizeProvider>
              ) : (
                <Story />
              )}
            </div>
          </CunninghamProvider>
        </I18nextProvider>
      );
    },
  ],
};

export default preview;
