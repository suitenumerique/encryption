import { CunninghamProvider } from '@gouvfr-lasuite/cunningham-react';
import { addons } from '@storybook/preview-api';
import type { Preview } from '@storybook/react';
import { themes } from '@storybook/theming';
import React, { useEffect, useState } from 'react';

const DARK_MODE_EVENT_NAME = 'DARK_MODE';

function useStorybookDarkMode(): boolean {
  const [isDark, setIsDark] = useState(false);

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
  parameters: {
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
    (Story) => {
      const isDark = useStorybookDarkMode();
      const cunninghamTheme = isDark ? 'dark' : 'default';

      // Also update the root element so any raw CSS using Cunningham variables works
      useEffect(() => {
        document.documentElement.classList.toggle('cunningham-theme--dark', isDark);
        document.documentElement.classList.toggle('cunningham-theme--default', !isDark);
      }, [isDark]);

      return (
        <CunninghamProvider theme={cunninghamTheme}>
          <div
            style={{
              padding: 'var(--c--globals--spacings--4, 16px)',
              background: 'var(--c--contextuals--background--surface--primary, #fff)',
              color: 'var(--c--contextuals--content--surface--primary, #161616)',
              minHeight: '100%',
            }}
          >
            <Story />
          </div>
        </CunninghamProvider>
      );
    },
  ],
  tags: ['autodocs'],
};

export default preview;
