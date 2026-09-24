import { Button, CunninghamProvider } from '@gouvfr-lasuite/cunningham-react';
import '@gouvfr-lasuite/cunningham-react/icons';
import '@gouvfr-lasuite/cunningham-react/style';
import { Icon } from '@gouvfr-lasuite/ui-kit';
import type { Preview } from '@storybook/react';
import { mswLoader } from 'msw-storybook-addon/csf3';
import { setupWorker } from 'msw/browser';
import { type ReactNode, useEffect, useState } from 'react';
import { I18nextProvider } from 'react-i18next';
import { addons } from 'storybook/preview-api';
import { themes } from 'storybook/theming';

import { useNavigationGuard } from '@encryption/.storybook/navigation-guard';
import i18n from '@encryption/src/i18n';
import { DEFAULT_LOCALE } from '@encryption/src/shared/locale';
import { CloseRequestProvider } from '@encryption/src/ui/hooks/useCloseRequest';
import type { EncryptionContextType } from '@encryption/src/ui/providers/EncryptionProvider';
import { defaultHandlers } from '@encryption/src/ui/testing/default-handlers';
import { MockEncryptionProvider } from '@encryption/src/ui/testing/mock-encryption';

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
      <div className="c__modal__close">
        <Button
          icon={<Icon aria-hidden name="close" />}
          variant="tertiary"
          color="neutral"
          size="small"
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

      const hostModal = context.parameters.hostModal as boolean | 'medium' | 'card' | undefined;

      // Also update the root element so any raw CSS using Cunningham variables
      // works, and paint the page itself: a centered story covers only its own
      // box, and what shows around it is the preview document, which knows
      // nothing of the theme otherwise.
      useEffect(() => {
        document.documentElement.classList.toggle('cunningham-theme--dark', isDark);
        document.documentElement.classList.toggle('cunningham-theme--default', !isDark);
        document.body.style.backgroundColor = hostModal
          ? 'var(--c--contextuals--background--surface--tertiary)'
          : 'var(--c--contextuals--background--surface--primary)';
      }, [isDark, hostModal]);

      // Fullscreen stories (a document PDF preview, an email, a docs page) only drop
      // the padding to go edge-to-edge; minHeight (not a fixed height) lets taller
      // content grow and scroll rather than being clipped.
      const isFullscreen = context.parameters.layout === 'fullscreen';

      // Interface screens are the content of the modal the interface draws over
      // the product (App.tsx). `hostModal` stands in for that chrome so a story
      // shows the screen at the width it really gets: the design system's small
      // modal (350px) or, for list-heavy screens, the medium one. The cross
      // raises the same close request the modal's does, so a screen holding a
      // guard reacts like it does in the product, and an unguarded one only logs.
      // `'card'` is the width alone, for a component that lives inside a screen.
      return (
        <I18nextProvider i18n={i18n}>
          <CunninghamProvider theme={cunninghamTheme}>
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
                <div
                  style={{
                    width: hostModal === 'medium' ? 600 : 350,
                    maxWidth: '100%',
                    boxSizing: 'border-box',
                    padding: 24,
                    borderRadius: 8,
                    background: 'var(--c--contextuals--background--surface--secondary, #fff)',
                    border: '1px solid var(--c--contextuals--border--surface--primary, #dfe2ea)',
                    boxShadow: '0 6px 20px rgba(0, 0, 18, 0.1)',
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
