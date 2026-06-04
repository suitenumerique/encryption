import type { StorybookConfig } from '@storybook/react-vite';
import path from 'path';

const config: StorybookConfig = {
  stories: [path.resolve(__dirname, '../src/**/*.stories.@(js|ts|jsx|tsx)')],
  addons: ['@storybook/addon-a11y', '@storybook/addon-docs', '@storybook/addon-interactions', '@storybook/addon-essentials', 'storybook-dark-mode'],
  framework: {
    name: '@storybook/react-vite',
    options: {},
  },
  core: {
    disableTelemetry: true,
  },
  viteFinal: async (config) => {
    config.resolve = config.resolve || {};
    config.resolve.alias = {
      ...(config.resolve.alias || {}),
      '@encryption': path.resolve(__dirname, '..'),
    };

    return config;
  },
};

export default config;
